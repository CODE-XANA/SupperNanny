use anyhow::{Context, Result};
use aya::{maps::perf::PerfEventArray, programs::TracePoint, util::online_cpus, Bpf};
use bytes::BytesMut;
use libc::kill;
use log::{info, warn};
use std::path::PathBuf;
use std::{
    collections::HashMap,
    fs,
    os::unix::io::{AsRawFd, FromRawFd},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    thread,
};
use tokio::signal;

use crate::ebpf::user::event::{ExecEvent, MAX_ARGS};

/// Démarre l’intercepteur eBPF et boucle sur les exec_events.
pub async fn run() -> Result<()> {
    info!("🔧 Loading eBPF program...");
    let mut bpf = Bpf::load_file(concat!(env!("OUT_DIR"), "/exec_intercept.o"))
        .context("Failed to load BPF program")?;
    let prog: &mut TracePoint = bpf
        .program_mut("exec_intercept")
        .context("Program exec_intercept not found")?
        .try_into()
        .context("Failed to cast to TracePoint")?;
    prog.load().context("Loading BPF prog failed")?;
    prog.attach("syscalls", "sys_enter_execve")
        .context("Failed to attach sys_enter_execve")?;
    prog.attach("syscalls", "sys_enter_execveat")
        .context("Failed to attach sys_enter_execveat")?;

    let map = bpf.take_map("EXEC_EVENTS").context("Map EXEC_EVENTS not found")?;
    let mut perf_array = PerfEventArray::try_from(map)?;
    for cpu in online_cpus().context("Failed to get CPUs")? {
        let mut buf = perf_array.open(cpu, None).context("open perf buffer")?;
        thread::spawn(move || {
            let mut bufs =
                vec![BytesMut::with_capacity(std::mem::size_of::<ExecEvent>())];
            loop {
                if let Err(e) = buf.read_events(&mut bufs) {
                    warn!("⚠️ read_events error on CPU {}: {}", cpu, e);
                    continue;
                }
                for b in &bufs {
                    if b.len() == std::mem::size_of::<ExecEvent>() {
                        let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ExecEvent) };
                        handle_exec_event(ev);
                    }
                }
                bufs.clear();
                bufs.push(BytesMut::with_capacity(std::mem::size_of::<ExecEvent>()));
            }
        });
    }

    signal::ctrl_c().await?;
    info!("👋 Shutdown interceptor");
    Ok(())
}

/// Vérifie si pid est dans un conteneur (cgroup ou namespace PID différent).
fn is_in_container(pid: u32) -> bool {
    if let Ok(cg) = fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        if cg.contains("/docker/") || cg.contains("docker-") || cg.contains("kubepods") {
            return true;
        }
    }
    let me = fs::read_link("/proc/self/ns/pid").ok();
    let them = fs::read_link(format!("/proc/{}/ns/pid", pid)).ok();
    matches!((me, them), (Some(m), Some(t)) if m != t)
}

/// Lit /proc/<pid>/environ en une map clef→valeur.
fn read_proc_environ(pid: u32) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(data) = fs::read_to_string(format!("/proc/{}/environ", pid)) {
        for var in data.split('\0') {
            if let Some(idx) = var.find('=') {
                let (k, v) = var.split_at(idx);
                map.insert(k.to_string(), v[1..].to_string());
            }
        }
    }
    map
}

/// Convertit les chemins relatifs des arguments en chemins absolus selon le cwd du PID.
fn absolutize_args(pid: u32, args: Vec<String>) -> Vec<String> {
    let cwd = fs::read_link(format!("/proc/{}/cwd", pid)).unwrap_or_else(|_| PathBuf::from("/"));
    args.into_iter()
        .map(|arg| {
            let path = PathBuf::from(&arg);
            if path.is_absolute() || arg.starts_with("-") {
                arg // option ou déjà absolu
            } else {
                let abs = cwd.join(&arg);
                if abs.exists() {
                    abs.to_string_lossy().into_owned()
                } else {
                    arg
                }
            }
        })
        .collect()
}


/// Reconstruit basename + argv depuis l’ExecEvent.
fn reconstruct_args(ev: &ExecEvent) -> (String, Vec<String>) {
    // basename
    let fullpath = {
        let raw = &ev.filename;
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..len]).into_owned()
    };
    let basename = Path::new(&fullpath)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&fullpath)
        .to_string();

    // argv
    let mut args = Vec::new();
    for i in 0..(ev.argc as usize).min(MAX_ARGS) {
        let raw = &ev.argv[i];
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let s = String::from_utf8_lossy(&raw[..len]).into_owned();
        if s.is_empty() || (args.is_empty() && s == basename) {
            continue;
        }
        args.push(s);
    }

    // scinder "-it"/"-ti"
    let mut pargs = Vec::new();
    for a in args {
        if a == "-it" || a == "-ti" {
            pargs.push("-i".into());
            pargs.push("-t".into());
        } else {
            pargs.push(a);
        }
    }

    (basename, pargs)
}

/// Ne reconnait **que** docker run -i -t …
fn is_interactive_docker_cmd(basename: &str, args: &[String]) -> bool {
    basename == "docker"
        && args.get(0).map_or(false, |a| a == "run")
        && args.iter().any(|a| a == "-i" || a == "--interactive")
        && args.iter().any(|a| a == "-t" || a == "--tty")
}

/// Lit `/proc/<pid>/cmdline` pour reconstruire argv.
fn get_cmdline(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|data| {
            data.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Gère chaque ExecEvent : kill original + lance supernanny <cmd> <args> en foreground.
fn handle_exec_event(ev: ExecEvent) {
    let pid = ev.pid;
    let uid = ev.uid;

    // 1) Lire l’environnement du processus
    let envs = read_proc_environ(pid);

    // 2) Sauvegarder le cwd d’origine
    let original_cwd = fs::read_link(format!("/proc/{}/cwd", pid))
        .unwrap_or_else(|_| PathBuf::from("/"));

    // 3) PPID + chemin de l’exécutable parent
    let ppid = fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()
        .and_then(|s| {
            s.lines()
             .find(|l| l.starts_with("PPid:"))
             .and_then(|l| l.split_whitespace().nth(1))
             .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(0);
    let parent_exe = fs::read_link(format!("/proc/{}/exe", ppid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // 4) Ne traiter que si fd0 est un vrai tty
    let tty = match fs::read_link(format!("/proc/{}/fd/0", pid)) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => return,
    };
    if !tty.starts_with("/dev/pts/") && !tty.starts_with("/dev/tty") {
        return;
    }

    // 4.5) Filtrer la tab-completion (stdout vers un pipe)
    if let Ok(out) = fs::read_link(format!("/proc/{}/fd/1", pid)) {
        let o = out.to_string_lossy();
        if !o.starts_with("/dev/pts/") && !o.starts_with("/dev/tty") {
            return;
        }
    }
    if envs.contains_key("COMP_LINE") || envs.contains_key("COMP_WORDS") {
        return;
    }

    // 5) GID original
    let gid = fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()
        .and_then(|s| {
            s.lines()
             .find(|l| l.starts_with("Gid:"))
             .and_then(|l| l.split_whitespace().nth(1))
             .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(uid);

    // 6) Skip si NO_INTERCEPT=1 et parent est déjà supernanny/xterm
    if envs.get("NO_INTERCEPT") == Some(&"1".into()) {
        if parent_exe.ends_with("supernanny") || parent_exe.ends_with("xterm") {
            return;
        }
    }

    // 7) Skip dans un conteneur
    if is_in_container(pid) {
        return;
    }

    // 8) Skip supernanny lui-même et UIDs < 1000
    let comm = {
        let raw = &ev.comm;
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..len]).into_owned()
    };
    if comm.contains("supernanny") || uid < 1000 {
        return;
    }

    // 9) Reconstruire basename + argv brut (splitting "-it"/"-ti")
    let (basename, raw_args) = {
        let raw_fn = &ev.filename;
        let fn_len = raw_fn.iter().position(|&b| b == 0).unwrap_or(raw_fn.len());
        let fullpath = String::from_utf8_lossy(&raw_fn[..fn_len]).into_owned();
        let base = Path::new(&fullpath)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&fullpath)
            .to_string();

        let mut tmp = Vec::new();
        for i in 0..(ev.argc as usize).min(MAX_ARGS) {
            let raw = &ev.argv[i];
            let l = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let s = String::from_utf8_lossy(&raw[..l]).into_owned();
            if !s.is_empty() {
                tmp.push(s);
            }
        }
        let mut pa = Vec::new();
        for s in tmp {
            if s == "-it" || s == "-ti" {
                pa.push("-i".into());
                pa.push("-t".into());
            } else {
                pa.push(s);
            }
        }
        (base, pa)
    };

    // 10) Skip les cas de base
    if ["xterm", "dash", "sh", "supernanny"].contains(&basename.as_str()) {
        return;
    }

    // 11) Extraire les vrais args (sans argv[0])
    let args: Vec<String> = if raw_args.first().map(|s| s == &basename).unwrap_or(false) {
        raw_args.iter().skip(1).cloned().collect()
    } else {
        raw_args.clone()
    };

    // 12) CAS SPÉCIAL : docker run -i -t … bash
    if basename == "docker"
        && args.get(0).map(|s| s == "run").unwrap_or(false)
        && args.iter().any(|s| s == "-i")
        && args.iter().any(|s| s == "-t")
    {
        info!("🔍 Intercepted interactive Docker run: {} {:?}", basename, args);
        unsafe { kill(pid as i32, libc::SIGKILL) };

        // préparer le lancement dans un xterm
        let display = envs.get("DISPLAY").cloned().unwrap_or_else(|| ":0".into());
        let xauth  = envs.get("XAUTHORITY").cloned().unwrap_or_else(|| {
            format!(
                "{}/.Xauthority",
                envs.get("HOME").map(String::as_str).unwrap_or("/home/user")
            )
        });

        let cmdline = reconstruct_args(&ev);
        let full_cmd = format!("/usr/bin/supernanny {} {}", cmdline.0, cmdline.1.join(" "));

        let mut cmd = Command::new("/usr/bin/xterm");
        cmd.env_remove("LD_PRELOAD")
           .arg("-hold")
           .arg("-e")
           .arg(&full_cmd)
           .env("DISPLAY", &display)
           .env("XAUTHORITY", &xauth)
           .env("NO_INTERCEPT", "1");
        if let Some(bus) = envs.get("DBUS_SESSION_BUS_ADDRESS") {
            cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
        }

        let _ = cmd.status();
        return;
    }

    // 13) Skip bash interactif sans LD_PRELOAD
    let has_preload      = envs.contains_key("LD_PRELOAD");
    let non_inter_bash   = basename == "bash" && !args.is_empty();
    if basename == "bash" && args.is_empty() && !has_preload {
        return;
    }

    // 14) ENFORCE : bash non-interactif (args≠vide) ou LD_PRELOAD
    if non_inter_bash || has_preload {
        info!("🔒 Enforcing supernanny on {} {:?}", basename, args);
        unsafe { kill(pid as i32, libc::SIGKILL) };

        let raw_fn = &ev.filename;
        let fn_len = raw_fn.iter().position(|&b| b == 0).unwrap_or(raw_fn.len());
        let fullpath = String::from_utf8_lossy(&raw_fn[..fn_len]).into_owned();

        let mut cmd = Command::new("/usr/bin/supernanny");
        cmd.current_dir(&original_cwd)
           .env_remove("LD_PRELOAD")
           .env("NO_INTERCEPT", "1")
           .arg(fullpath.as_str())
           .args(&args);
        if let Some(bus) = envs.get("DBUS_SESSION_BUS_ADDRESS") {
            cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
        }

        let tty_f = fs::OpenOptions::new().read(true).write(true).open(&tty).unwrap();
        let fd    = tty_f.as_raw_fd();
        let in_fd  = unsafe { libc::dup(fd) };
        let out_fd = unsafe { libc::dup(fd) };
        let err_fd = unsafe { libc::dup(fd) };
        cmd.stdin  (unsafe { Stdio::from_raw_fd(in_fd) })
           .stdout (unsafe { Stdio::from_raw_fd(out_fd) })
           .stderr (unsafe { Stdio::from_raw_fd(err_fd) });
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                libc::ioctl(fd, libc::TIOCSCTTY, 0);
                libc::setgid(gid);
                libc::setuid(uid);
                Ok(())
            });
        }
        let _ = cmd.status();
        return;
    }

    // 15) CATCH-ALL : tous les autres binaires
    info!("🔍 Intercepted: {} → {:?}", basename, args);
    unsafe { kill(pid as i32, libc::SIGKILL) };

    let mut cmd = Command::new("/usr/bin/supernanny");
    cmd.current_dir(&original_cwd)
       .env_remove("LD_PRELOAD")
       .env("NO_INTERCEPT", "1")
       .arg(&basename)
       .args(&args);
    if let Some(bus) = envs.get("DBUS_SESSION_BUS_ADDRESS") {
        cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
    }

    let tty_f = fs::OpenOptions::new().read(true).write(true).open(&tty).unwrap();
    let fd    = tty_f.as_raw_fd();
    let in_fd  = unsafe { libc::dup(fd) };
    let out_fd = unsafe { libc::dup(fd) };
    let err_fd = unsafe { libc::dup(fd) };
    cmd.stdin  (unsafe { Stdio::from_raw_fd(in_fd) })
       .stdout (unsafe { Stdio::from_raw_fd(out_fd) })
       .stderr (unsafe { Stdio::from_raw_fd(err_fd) });
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            libc::ioctl(fd, libc::TIOCSCTTY, 0);
            libc::setgid(gid);
            libc::setuid(uid);
            Ok(())
        });
    }
    let _ = cmd.status();
}
