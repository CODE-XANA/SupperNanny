use anyhow::{anyhow, Context, Result};
use dialoguer::{Input, Select};
use landlock::{
    Access, AccessFs, AccessNet, ABI, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};
use regex::Regex;
use reqwest::blocking::Client;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use tempfile::TempDir;
use supernanny_sandboxer::policy_client::RuleSet;
use supernanny_sandboxer::policy_client::{User, log_denial_event};
use serde::{Deserialize, Serialize};

// ----------------------------------------------------------------------------
// AppPolicy
// ----------------------------------------------------------------------------

#[derive(Debug)]
pub struct AppPolicy {
    ro_paths: HashSet<PathBuf>,
    rw_paths: HashSet<PathBuf>,
    tcp_bind: HashSet<u16>,
    tcp_connect: HashSet<u16>,
    allowed_ips: HashSet<String>,
    allowed_domains: HashSet<String>,
}

#[derive(Debug, Deserialize)]
struct RoleCheckResponse {
    permissions: Vec<String>,
}

#[derive(Serialize)]
struct PolicyPayload {
    app_name: String,
    role_id: i32,
    default_ro: String,
    default_rw: String,
    tcp_bind: String,
    tcp_connect: String,
    allowed_ips: String,
    allowed_domains: String,
}

impl From<RuleSet> for AppPolicy {
    fn from(rs: RuleSet) -> Self {
        Self {
            ro_paths: rs.ro_paths,
            rw_paths: rs.rw_paths,
            tcp_bind: rs.tcp_bind,
            tcp_connect: rs.tcp_connect,
            allowed_ips: rs.allowed_ips,
            allowed_domains: rs.allowed_domains,
        }
    }
}

impl AppPolicy {
    fn contains_path(&self, path: &Path) -> bool {
        self.ro_paths.contains(path) || self.rw_paths.contains(path)
    }

    fn join_paths(paths: &HashSet<PathBuf>) -> String {
        paths.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join(":")
    }

    fn join_ports(ports: &HashSet<u16>) -> String {
        ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(":")
    }

    fn join_ips(ips: &HashSet<String>) -> String {
        ips.iter().cloned().collect::<Vec<_>>().join(":")
    }

    fn join_domains(domains: &HashSet<String>) -> String {
        domains.iter().cloned().collect::<Vec<_>>().join(":")
    }
}

// ----------------------------------------------------------------------------
// Auth: just token
// ----------------------------------------------------------------------------

fn get_credentials() -> Result<(String, User)> {
    let username = Input::<String>::new()
        .with_prompt("Username")
        .interact_text()
        .context("Failed to read username")?;
    
    let password = dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .context("Failed to read password")?;
    
    RuleSet::login(&username, &password)
        .context("Authentication failed")
}

// ----------------------------------------------------------------------------
// Server communication
// ----------------------------------------------------------------------------

pub fn update_policy_on_server(app: &str, policy: &AppPolicy, token: &str) -> Result<()> {
    let base_url = env::var("SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3005".into());
    let client = Client::new();

    // 🔎 Step 1: Check if user has "manage_policies"
    let roles_url = format!("{}/auth/roles", base_url);
    let res = client
        .get(&roles_url)
        .bearer_auth(token)
        .send()
        .context("Failed to fetch user permissions")?;

    if !res.status().is_success() {
        return Err(anyhow!("Could not verify user permissions: {}", res.status()));
    }

    let roles_info: RoleCheckResponse = res
        .json()
        .context("Failed to parse roles response")?;

    if !roles_info.permissions.contains(&"manage_policies".to_string()) {
        println!("🚫 User does not have 'manage_policies' permission. Skipping policy update.");
        return Ok(());
    }

    // Step 2: Send the policy update
    let update_url = format!("{}/auth/ruleset/update", base_url);

    let payload = PolicyPayload {
        app_name: app.to_string(),
        role_id: 1, // You may keep it static or decode from JWT if needed
        default_ro: AppPolicy::join_paths(&policy.ro_paths),
        default_rw: AppPolicy::join_paths(&policy.rw_paths),
        tcp_bind: AppPolicy::join_ports(&policy.tcp_bind),
        tcp_connect: AppPolicy::join_ports(&policy.tcp_connect),
        allowed_ips: AppPolicy::join_ips(&policy.allowed_ips),
        allowed_domains: AppPolicy::join_domains(&policy.allowed_domains),
    };

    let res = client
        .post(&update_url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .context("Failed to send policy update")?;

    if !res.status().is_success() {
        return Err(anyhow!("Policy update failed: {}", res.status()));
    }

    println!("✅ Policy update successfully posted to server!");
    Ok(())
}




// ----------------------------------------------------------------------------
// Landlock
// ----------------------------------------------------------------------------

fn enforce_landlock(policy: &AppPolicy) -> Result<()> {
    let abi = ABI::V5;
    let base = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::BindTcp)?
        .handle_access(AccessNet::ConnectTcp)?;

    let mut created = base.create().context("Failed to create Landlock ruleset")?;

    for path in &policy.ro_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str())?;
            created = created.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))?;
        }
    }

    for path in &policy.rw_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str())?;
            created = created.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?;
        }
    }

    for port in &policy.tcp_bind {
        created = created.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
    }

    for port in &policy.tcp_connect {
        created = created.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
    }

    created.restrict_self()?;
    Ok(())
}

// ----------------------------------------------------------------------------
// Strace
// ----------------------------------------------------------------------------

fn run_strace(app_path: &Path, args: &[String], policy: &AppPolicy, prefix: &str) -> Result<(ExitStatus, TempDir)> {
    let tempdir = TempDir::new()?;
    let log_prefix = tempdir.path().join(prefix);
    let log_path = log_prefix.to_string_lossy().to_string();

    let mut envs: Vec<(String, String)> = env::vars().collect();
    envs.push(("LL_FS_RO".into(), AppPolicy::join_paths(&policy.ro_paths)));
    envs.push(("LL_FS_RW".into(), AppPolicy::join_paths(&policy.rw_paths)));
    envs.push(("LL_TCP_BIND".into(), AppPolicy::join_ports(&policy.tcp_bind)));
    envs.push(("LL_TCP_CONNECT".into(), AppPolicy::join_ports(&policy.tcp_connect)));
    envs.push(("LL_ALLOWED_IPS".into(), AppPolicy::join_ips(&policy.allowed_ips)));
    envs.push(("LL_ALLOWED_DOMAINS".into(), AppPolicy::join_domains(&policy.allowed_domains)));

    let current_exe = env::current_exe()?;
    let strace_path = env::var("STRACE_PATH").unwrap_or_else(|_| "/usr/bin/strace".to_string());

    let status = Command::new(strace_path)
        .args(&["-ff", "-yy", "-e", "trace=file,process,openat,getdents,stat,connect,socket,bind"])
        .arg("-o").arg(&log_path)
        .arg(&current_exe)
        .arg("--sandbox")
        .arg(app_path)
        .args(args)
        .env_clear()
        .envs(envs)
        .status()?;

    Ok((status, tempdir))
}

fn parse_denied_lines(dir: &Path, prefix: &str) -> Result<HashSet<String>> {
    let path_re = Regex::new(r#"openat\(.*?,\s*"([^"]+)"|stat\("([^"]+)"|getdents\(.*?,\s*"([^"]+)""#)?;
    let net_re = Regex::new(r#"(connect|bind)\(.*?sin_port=htons\((\d+)\)"#)?;

    let mut denials = HashSet::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }

        for line in BufReader::new(File::open(entry.path())?).lines() {
            let line = line?;
            if !(line.contains("EACCES") || line.contains("EPERM")) {
                continue;
            }

            if let Some(cap) = path_re.captures(&line) {
                if let Some(p) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
                    let raw_path = PathBuf::from(p.as_str());
                
                    let canonical_path = fs::canonicalize(&raw_path).unwrap_or(raw_path);
                
                    denials.insert(canonical_path.to_string_lossy().to_string());
                }
                
            } else if let Some(cap) = net_re.captures(&line) {
                if let (Some(op), Some(port)) = (cap.get(1), cap.get(2)) {
                    denials.insert(format!("tcp:{}:{}", op.as_str(), port.as_str()));
                }
            }
        }
    }

    Ok(denials)
}

fn process_denials(denials: HashSet<String>, policy: &mut AppPolicy) -> Result<bool> {
    let mut updated = false;

    for entry in denials {
        if entry.starts_with("tcp:") {
            let parts: Vec<&str> = entry.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let (_, op, port_str) = (parts[0], parts[1], parts[2]);
                let port: u16 = port_str.parse().with_context(|| format!("Invalid TCP port: {}", port_str))?;
                
                let choices = &["Allow", "Deny"];
                let selection = Select::new()
                    .with_prompt(format!("TCP {} port {} denied. Allow?", op, port))
                    .items(choices)
                    .default(1)
                    .interact()?;

                if selection == 0 {
                    if op == "connect" {
                        policy.tcp_connect.insert(port);
                        updated = true;
                    } else if op == "bind" {
                        policy.tcp_bind.insert(port);
                        updated = true;
                    }
                }
            }
        } else {
            let path = PathBuf::from(&entry);

            let canonical_path = fs::canonicalize(&path).unwrap_or(path.clone()); // fallback to original
            if policy.contains_path(&canonical_path) {
                continue;
            }
            
            let choices = &["Read-Only", "Read-Write", "Deny"];
            let selection = Select::new()
                .with_prompt(format!("Denied path: {}. Allow as?", canonical_path.display()))
                .items(choices)
                .default(2)
                .interact()?;
            
            match selection {
                0 => {
                    policy.ro_paths.insert(canonical_path);
                    updated = true;
                },
                1 => {
                    policy.rw_paths.insert(canonical_path);
                    updated = true;
                },
                _ => {}
            };
            
        }
    }

    Ok(updated)
}

// ----------------------------------------------------------------------------
// Entrypoint
// ----------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Special --sandbox execution for the strace’d command
    if args.len() >= 2 && args[1] == "--sandbox" {
        return run_sandbox();
    }

    // Authenticate and get token + user object
    let (token, user) = get_credentials().context("Failed to authenticate user")?;
    println!("Authentication successful!");

    // Validate command line usage
    if args.len() < 2 {
        return Err(anyhow!("Usage: {} <APP> [ARGS...]", args[0]));
    }

    let app = &args[1];
    let app_args = &args[2..];

    // Retrieve policy from server
    let ruleset = RuleSet::fetch_for_app(app, &token)
        .context("Failed to fetch policy from server")?;
    let mut policy = AppPolicy::from(ruleset);

    // First run
    let (status, tempdir) = run_strace(Path::new(app), app_args, &policy, "sandbox_log")?;
    let denials = parse_denied_lines(tempdir.path(), "sandbox_log")?;

    // Log denials if any
    if !denials.is_empty() {
        for denial in &denials {
            let resource_type = if denial.starts_with("tcp:") {
                "network"
            } else {
                "filesystem"
            };

            let _ = log_denial_event(app, denial, resource_type, &token);
        }
    }

    // Check if rerun is needed
    if !status.success() || !denials.is_empty() {
        if user.has_permission("manage_policies") {
            let updated = process_denials(denials.clone(), &mut policy)?;
            if updated {
                update_policy_on_server(app, &policy, &token)
                    .context("Failed to upload updated policy")?;
        
                let rerun = dialoguer::Confirm::new()
                    .with_prompt("Rerun with updated policy?")
                    .default(true)
                    .interact()
                    .unwrap_or(false);
        
                if rerun {
                    let (_rerun_status, _rerun_temp) = run_strace(Path::new(app), app_args, &policy, "rerun_log")?;
                    println!("Second run completed.");
                }
            } else {
                println!("No changes to apply.");
            }
        }        
        else {
            println!("Access denied events have been logged. Contact an admin if access is needed.");
            for denial in &denials {
                println!("  - Denied: {}", denial);
            }
        }
    } else {
        println!("App ran successfully with current policy.");
    }

    Ok(())
}


fn run_sandbox() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err(anyhow!("Usage: {} --sandbox <APP> [ARGS...]", args[0]));
    }

    let cmd = &args[2];
    let cmd_args = &args[3..];
    
    let policy = AppPolicy {
        ro_paths: env::var("LL_FS_RO").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect(),
        rw_paths: env::var("LL_FS_RW").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect(),
        tcp_bind: env::var("LL_TCP_BIND").unwrap_or_default().split(':').filter_map(|s| s.parse().ok()).collect(),
        tcp_connect: env::var("LL_TCP_CONNECT").unwrap_or_default().split(':').filter_map(|s| s.parse().ok()).collect(),
        allowed_ips: env::var("LL_ALLOWED_IPS").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(String::from).collect(),
        allowed_domains: env::var("LL_ALLOWED_DOMAINS").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(String::from).collect(),
    };

    // Get token for event logging
    let token = env::var("LL_AUTH_TOKEN").ok();
    
    match enforce_landlock(&policy) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("Warning: Failed to apply Landlock restrictions: {}", e);
            // Try to log the error if we have a token
            if let Some(token) = &token {
                let _ = log_denial_event(cmd, &format!("landlock_setup_error:{}", e), "system", token);
            }
        },
    }
    
    let status = Command::new(cmd).args(cmd_args).status()?;
    
    // If command failed and we have a token, try to log a general failure
    if !status.success() && token.is_some() {
        let _ = log_denial_event(cmd, &format!("exit_status:{}", status), "application", &token.unwrap());
    }
    
    std::process::exit(status.code().unwrap_or(1));
}
