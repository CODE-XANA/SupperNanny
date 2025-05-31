// src/dispatcher.rs

use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use anyhow::{anyhow, Result};
use crate::ebpf::user::event::ExecEvent;
use std::{
    fs::{self, OpenOptions},
    os::unix::io::AsRawFd,
    process::{Command, Stdio},
};
use libc;

/// Lit `/proc/<pid>/cmdline`, retourne Vec<String> des arguments.
fn get_cmdline(pid: u32) -> Result<Vec<String>> {
    let data = fs::read(format!("/proc/{}/cmdline", pid))?;
    Ok(data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// Lit `/proc/<pid>/fd/0` pour trouver le TTY.
fn get_tty(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{}/fd/0", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Tue le process et relance via supernanny sur le même TTY.
pub fn dispatch_event(event: ExecEvent) -> Result<()> {
    // 1) Nom du binaire
    let filename = String::from_utf8_lossy(&event.filename)
        .trim_end_matches('\0')
        .to_string();
    if filename.starts_with("/usr/bin/supernanny") {
        return Ok(());
    }

    // 2) Arguments depuis /proc/<pid>/cmdline
    let mut args = get_cmdline(event.pid)
        .map_err(|e| anyhow!("Impossible de lire cmdline: {}", e))?;
    if !args.is_empty() {
        args[0] = filename.clone();
    } else {
        args.insert(0, filename.clone());
    }

    // 3) Récupération du TTY
    let tty_path = get_tty(event.pid)
        .ok_or_else(|| anyhow!("Pas de TTY pour PID {}", event.pid))?;
    let tty = OpenOptions::new().read(true).write(true).open(&tty_path)?;
    let fd = tty.as_raw_fd();

    // 4) Dup des FDs
    let stdin_fd = unsafe { libc::dup(fd) };
    let stdout_fd = unsafe { libc::dup(fd) };
    let stderr_fd = unsafe { libc::dup(fd) };
    if stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0 {
        return Err(anyhow!("dup() a échoué"));
    }

    // 5) Kill le process original
    unsafe { libc::kill(event.pid as i32, libc::SIGKILL) };

    // 6) Exécution de supernanny
    // Construisons la Command avant d'appeler exec
    let mut cmd = Command::new("/usr/bin/supernanny");
    cmd.args(&args)
        .stdin(unsafe { Stdio::from_raw_fd(stdin_fd) })
        .stdout(unsafe { Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { Stdio::from_raw_fd(stderr_fd) });

    // Note : pre_exec est unsafe
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            libc::ioctl(fd, libc::TIOCSCTTY, 0);
            Ok(())
        });
    }

    // Remplace le process actuel
    cmd.exec();

    Ok(())
}
