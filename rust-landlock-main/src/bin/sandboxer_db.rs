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
// Constants for limiting policy expansion
// ----------------------------------------------------------------------------

const MAX_RO_PATHS: usize = 100;
const MAX_RW_PATHS: usize = 50;
const MAX_TCP_BIND_PORTS: usize = 20;
const MAX_TCP_CONNECT_PORTS: usize = 30;
const MAX_IPS: usize = 50;
const MAX_DOMAINS: usize = 50;

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

    // Validate a path is safe to use
    fn validate_path(path: &Path) -> Result<()> {
        // Check path isn't too long
        if path.to_string_lossy().len() > 4096 {
            return Err(anyhow!("Path too long: {}", path.display()));
        }
        
        // Check path doesn't contain unusual characters
        if path.to_string_lossy().contains('\0') {
            return Err(anyhow!("Path contains null bytes: {}", path.display()));
        }
        
        Ok(())
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
    
    let mut password = dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .context("Failed to read password")?;

    // Get the result before clearing password
    let result = RuleSet::login(&username, &password);
    
    // Clear password from memory as soon as possible
    let password_bytes = unsafe { password.as_bytes_mut() };
    for byte in password_bytes {
        *byte = 0;
    }
    drop(password);
    
    result.context("Authentication failed")
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
        println!("User does not have 'manage_policies' permission. Skipping policy update.");
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

    println!("Policy update successfully posted to server!");
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
    
    // Process read-only paths
    for path in &policy.ro_paths {
        if let Err(e) = AppPolicy::validate_path(path) {
            eprintln!("Warning: Skipping invalid read-only path: {}", e);
            continue;
        }
        
        let canonical_path = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: Failed to canonicalize path {}: {}", path.display(), e);
                continue;
            }
        };
        
        let fd = match PathFd::new(canonical_path.as_os_str()) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("Warning: Failed to open path {}: {}", canonical_path.display(), e);
                continue;
            }
        };
        
        let rule = PathBeneath::new(fd, AccessFs::from_read(abi));
        created = created.add_rule(rule)
            .map_err(|e| {
                eprintln!("Warning: Failed to add read-only rule for {}: {}", path.display(), e);
                e
            })?;
    }
    
    // Process read-write paths
    for path in &policy.rw_paths {
        if let Err(e) = AppPolicy::validate_path(path) {
            eprintln!("Warning: Skipping invalid read-write path: {}", e);
            continue;
        }
        
        let canonical_path = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: Failed to canonicalize path {}: {}", path.display(), e);
                continue;
            }
        };
        
        let fd = match PathFd::new(canonical_path.as_os_str()) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("Warning: Failed to open path {}: {}", canonical_path.display(), e);
                continue;
            }
        };
        
        let rule = PathBeneath::new(fd, AccessFs::from_all(abi));
        created = created.add_rule(rule)
            .map_err(|e| {
                eprintln!("Warning: Failed to add read-write rule for {}: {}", path.display(), e);
                e
            })?;
    }
    
    // Process TCP bind ports
    for port in &policy.tcp_bind {
        let rule = NetPort::new(*port, AccessNet::BindTcp);
        created = created.add_rule(rule)
            .map_err(|e| {
                eprintln!("Warning: Failed to add TCP bind rule for port {}: {}", port, e);
                e
            })?;
    }
    
    // Process TCP connect ports
    for port in &policy.tcp_connect {
        let rule = NetPort::new(*port, AccessNet::ConnectTcp);
        created = created.add_rule(rule)
            .map_err(|e| {
                eprintln!("Warning: Failed to add TCP connect rule for port {}: {}", port, e);
                e
            })?;
    }
    
    created.restrict_self()?;
    Ok(())
}


// ----------------------------------------------------------------------------
// Strace
// ----------------------------------------------------------------------------

fn run_strace(app_path: &Path, args: &[String], policy: &AppPolicy, prefix: &str) -> Result<(ExitStatus, TempDir)> {
    // Validate app path
    if let Err(e) = AppPolicy::validate_path(app_path) {
        return Err(anyhow!("Invalid application path: {}", e));
    }

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

        let file = match File::open(entry.path()) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: Could not open log file {}: {}", entry.path().display(), e);
                continue;
            }
        };

        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Warning: Error reading log line: {}", e);
                    continue;
                }
            };
            
            if !(line.contains("EACCES") || line.contains("EPERM")) {
                continue;
            }

            if let Some(cap) = path_re.captures(&line) {
                if let Some(p) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
                    let raw_path = PathBuf::from(p.as_str());
                
                    // Only canonicalize paths if possible, otherwise use the raw path
                    match fs::canonicalize(&raw_path) {
                        Ok(canonical_path) => {
                            denials.insert(canonical_path.to_string_lossy().to_string());
                        },
                        Err(_) => {
                            // If canonicalization fails, use the original path but mark it
                            denials.insert(format!("NONCANONICAL:{}", raw_path.to_string_lossy()));
                        }
                    }
                }
                
            } else if let Some(cap) = net_re.captures(&line) {
                if let (Some(op), Some(port)) = (cap.get(1), cap.get(2)) {
                    // Validate port is a valid number before adding
                    if let Ok(port_num) = port.as_str().parse::<u16>() {
                        denials.insert(format!("tcp:{}:{}", op.as_str(), port_num));
                    } else {
                        eprintln!("Warning: Invalid port number in denial log: {}", port.as_str());
                    }
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
            // Existing TCP port handling with original limits
            let parts: Vec<&str> = entry.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let (_, op, port_str) = (parts[0], parts[1], parts[2]);
                
                let port: u16 = match port_str.parse() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Warning: Invalid TCP port '{}': {}", port_str, e);
                        continue;
                    }
                };
                
                let choices = &["Allow", "Deny"];
                let selection = Select::new()
                    .with_prompt(format!("TCP {} port {} denied. Allow?", op, port))
                    .items(choices)
                    .default(1)
                    .interact()?;

                if selection == 0 {
                    if op == "connect" {
                        if policy.tcp_connect.len() >= MAX_TCP_CONNECT_PORTS {
                            println!("Warning: Maximum TCP connect ports ({}) reached", MAX_TCP_CONNECT_PORTS);
                            continue;
                        }
                        policy.tcp_connect.insert(port);
                        updated = true;
                    } else if op == "bind" {
                        if policy.tcp_bind.len() >= MAX_TCP_BIND_PORTS {
                            println!("Warning: Maximum TCP bind ports ({}) reached", MAX_TCP_BIND_PORTS);
                            continue;
                        }
                        policy.tcp_bind.insert(port);
                        updated = true;
                    }
                }
            }
        } else if entry.starts_with("ip:") {
            // New IP address handling with MAX_IPS
            let ip = entry.strip_prefix("ip:").unwrap_or(&entry);
            
            if policy.allowed_ips.len() >= MAX_IPS {
                println!("Warning: Maximum allowed IPs ({}) reached", MAX_IPS);
                continue;
            }
            
            let choices = &["Allow", "Deny"];
            let selection = Select::new()
                .with_prompt(format!("IP address {} denied. Allow?", ip))
                .items(choices)
                .default(1)
                .interact()?;

            if selection == 0 {
                policy.allowed_ips.insert(ip.to_string());
                updated = true;
            }
        } else if entry.starts_with("domain:") {
            // New domain handling with MAX_DOMAINS
            let domain = entry.strip_prefix("domain:").unwrap_or(&entry);
            
            if policy.allowed_domains.len() >= MAX_DOMAINS {
                println!("Warning: Maximum allowed domains ({}) reached", MAX_DOMAINS);
                continue;
            }
            
            let choices = &["Allow", "Deny"];
            let selection = Select::new()
                .with_prompt(format!("Domain {} denied. Allow?", domain))
                .items(choices)
                .default(1)
                .interact()?;

            if selection == 0 {
                policy.allowed_domains.insert(domain.to_string());
                updated = true;
            }
        }else {
            // Handle non-canonical paths specially
            let is_noncanonical = entry.starts_with("NONCANONICAL:");
            let path_str = if is_noncanonical {
                entry.strip_prefix("NONCANONICAL:").unwrap_or(&entry)
            } else {
                &entry
            };
            
            let path = PathBuf::from(path_str);

            // Validate the path
            if let Err(e) = AppPolicy::validate_path(&path) {
                eprintln!("Warning: Skipping invalid path: {}", e);
                continue;
            }

            // If we couldn't canonicalize earlier, try again now
            let canonical_path = if is_noncanonical {
                match fs::canonicalize(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Warning: Still unable to canonicalize path {}: {}", path.display(), e);
                        // Skip paths we can't canonicalize for safety
                        continue;
                    }
                }
            } else {
                path.clone()
            };

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
                    // Check limits before adding
                    if policy.ro_paths.len() >= MAX_RO_PATHS {
                        println!("Warning: Maximum number of read-only paths ({}) reached.", MAX_RO_PATHS);
                        continue;
                    }
                    policy.ro_paths.insert(canonical_path);
                    updated = true;
                },
                1 => {
                    // Check limits before adding
                    if policy.rw_paths.len() >= MAX_RW_PATHS {
                        println!("Warning: Maximum number of read-write paths ({}) reached.", MAX_RW_PATHS);
                        continue;
                    }
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

    // Special --sandbox execution for the strace'd command
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

    // Validate app path
    let app_path = Path::new(app);
    if let Err(e) = AppPolicy::validate_path(app_path) {
        return Err(anyhow!("Invalid application path: {}", e));
    }

    // Retrieve policy from server
    let ruleset = RuleSet::fetch_for_app(app, &token)
        .context("Failed to fetch policy from server")?;
    let mut policy = AppPolicy::from(ruleset);

    // First run
    let (status, tempdir) = run_strace(app_path, app_args, &policy, "sandbox_log")?;
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
                    let (_rerun_status, _rerun_temp) = run_strace(app_path, app_args, &policy, "rerun_log")?;
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
    
    // Validate command path
    let cmd_path = Path::new(cmd);
    if let Err(e) = AppPolicy::validate_path(cmd_path) {
        return Err(anyhow!("Invalid command path: {}", e));
    }
    
    let policy = AppPolicy {
        ro_paths: env::var("LL_FS_RO").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect(),
        rw_paths: env::var("LL_FS_RW").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect(),
        tcp_bind: env::var("LL_TCP_BIND").unwrap_or_default().split(':').filter_map(|s| s.parse().ok()).collect(),
        tcp_connect: env::var("LL_TCP_CONNECT").unwrap_or_default().split(':').filter_map(|s| s.parse().ok()).collect(),
        allowed_ips: env::var("LL_ALLOWED_IPS").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(String::from).collect(),
        allowed_domains: env::var("LL_ALLOWED_DOMAINS").unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(String::from).collect(),
    };

    // Get token for event logging but remove it from environment
    let token = env::var("LL_AUTH_TOKEN").ok();
    // Remove sensitive env vars so they aren't passed to the sandboxed application
    std::env::remove_var("LL_AUTH_TOKEN");
    
    // Apply Landlock restrictions - fail closed for security
    if let Err(e) = enforce_landlock(&policy) {
        eprintln!("Error: Failed to apply Landlock restrictions: {}", e);
        // Try to log the error if we have a token
        if let Some(token) = &token {
            let _ = log_denial_event(cmd, &format!("landlock_setup_error:{}", e), "system", token);
        }
        // Fail closed for security
        return Err(anyhow!("Cannot run without sandbox protection: {}", e));
    }
    
    // Execute the sandboxed command
    let status = Command::new(cmd).args(cmd_args).status()?;
    
    // If command failed and we have a token, try to log a general failure
    if !status.success() && token.is_some() {
        let _ = log_denial_event(cmd, &format!("exit_status:{}", status), "application", &token.unwrap());
    }
    
    std::process::exit(status.code().unwrap_or(1));
}