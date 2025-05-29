use anyhow::{anyhow, Context, Result};
use dialoguer::{Input, Select};
use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use regex::Regex;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use supernanny_sandboxer::policy_client::RuleSet;
use supernanny_sandboxer::policy_client::{log_denial_event, User};
use tempfile::TempDir;
use zeroize::Zeroize;

// ----------------------------------------------------------------------------
// Constants for limiting policy expansion
// ----------------------------------------------------------------------------

const MAX_RO_PATHS: usize = 100;
const MAX_RW_PATHS: usize = 50;
const MAX_TCP_BIND_PORTS: usize = 20;
const MAX_TCP_CONNECT_PORTS: usize = 30;
const MAX_IPS: usize = 50;
const MAX_DOMAINS: usize = 50;

// Token cache settings (matching PAM module)
const TOKEN_CACHE_DIR: &str = "supernanny";
const TOKEN_CACHE_FILE: &str = "session.cache";

// ----------------------------------------------------------------------------
// PAM Token Cache Integration
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct CachedToken {
    token: String,
    username: String,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() >= self.expires_at
    }

    fn is_near_expiry(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        (self.expires_at - now) < 1800 // 30 minutes
    }
}

fn get_cache_dir_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{}/{}", uid, TOKEN_CACHE_DIR))
}

fn get_cache_file_path(uid: u32) -> PathBuf {
    get_cache_dir_path(uid).join(TOKEN_CACHE_FILE)
}

fn load_cached_token(uid: u32) -> Result<CachedToken> {
    let file = get_cache_file_path(uid);
    let mut f = File::open(&file)
        .with_context(|| format!("Failed to open token cache file: {}", file.display()))?;
    let mut s = String::new();
    f.read_to_string(&mut s)
        .context("Failed to read token cache file")?;
    
    let token: CachedToken = serde_json::from_str(&s)
        .context("Failed to parse cached token")?;
    
    Ok(token)
}

fn refresh_auth_token(refresh_token: &str, username: &str) -> Result<CachedToken> {
    let url = env::var("SUPERNANNY_SERVER_URL")
        .unwrap_or_else(|_| "https://127.0.0.1:8443".into());
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?;
    
    let resp = client
        .post(&format!("{}/auth/refresh", url))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .context("Failed to send refresh token request")?;
    
    if !resp.status().is_success() {
        return Err(anyhow!("Token refresh failed: {}", resp.status()));
    }
    
    #[derive(serde::Deserialize)]
    struct RefreshResponse {
        token: String,
        #[serde(default)]
        refresh_token: Option<String>,
    }
    
    let refresh_resp: RefreshResponse = resp.json()
        .context("Failed to parse refresh response")?;
    
    use std::time::{SystemTime, UNIX_EPOCH};
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 8 * 3600; // 8 hours
    
    Ok(CachedToken {
        token: refresh_resp.token,
        username: username.to_string(),
        expires_at,
        refresh_token: refresh_resp.refresh_token,
    })
}

fn save_cached_token(uid: u32, token: &CachedToken) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    
    let dir = get_cache_dir_path(uid);
    fs::create_dir_all(&dir)
        .context("Failed to create cache directory")?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .context("Failed to set cache directory permissions")?;
    
    let file = get_cache_file_path(uid);
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&file)
        .context("Failed to open cache file for writing")?;
    
    f.write_all(serde_json::to_string_pretty(token)?.as_bytes())
        .context("Failed to write token to cache file")?;
    
    Ok(())
}

fn get_current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn get_current_username() -> Result<String> {
    let uid = get_current_uid();
    let output = Command::new("id")
        .arg("-un")
        .arg(uid.to_string())
        .output()
        .context("Failed to get username from UID")?;
    
    if !output.status.success() {
        return Err(anyhow!("Failed to resolve username for UID {}", uid));
    }
    
    let username = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in username")?
        .trim()
        .to_string();
    
    if username.is_empty() {
        return Err(anyhow!("Empty username for UID {}", uid));
    }
    
    Ok(username)
}

// ----------------------------------------------------------------------------
// Enhanced Credentials struct
// ----------------------------------------------------------------------------

#[derive(Debug)]
struct Credentials {
    username: String,
    token: String,
    _user: Option<User>, // Made optional since we might not have User object from cache
}

impl Credentials {
    fn new(username: String, token: String, user: Option<User>) -> Self {
        Self {
            username,
            token,
            _user: user,
        }
    }
}

fn get_credentials() -> Result<Credentials> {
    let uid = get_current_uid();
    let current_username = get_current_username()
        .context("Failed to determine current username")?;
    
    // Try to load cached token first
    match load_cached_token(uid) {
        Ok(cached) => {
            // Verify the cached token belongs to the current user
            if cached.username != current_username {
                return Err(anyhow!(
                    "Cached token belongs to different user: {} (expected: {})",
                    cached.username,
                    current_username
                ));
            }
            
            // Check if token is expired
            if cached.is_expired() {
                return Err(anyhow!("Cached authentication token has expired. Please log in again."));
            }
            
            // Check if token is near expiry and try to refresh
            if cached.is_near_expiry() {
                if let Some(ref refresh_token) = cached.refresh_token {
                    println!("Authentication token expires soon, attempting refresh...");
                    
                    match refresh_auth_token(refresh_token, &cached.username) {
                        Ok(new_token) => {
                            // Save the refreshed token
                            if let Err(e) = save_cached_token(uid, &new_token) {
                                eprintln!("Warning: Failed to save refreshed token: {}", e);
                                // Continue with the new token anyway
                            } else {
                                println!("Authentication token refreshed successfully");
                            }
                            
                            return Ok(Credentials::new(
                                new_token.username.clone(),
                                new_token.token.clone(),
                                None, // We don't have User object from refresh
                            ));
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to refresh token: {}", e);
                            // Fall back to using the current token if it's still valid
                            if !cached.is_expired() {
                                println!("Using existing token (refresh failed but token still valid)");
                                return Ok(Credentials::new(
                                    cached.username.clone(),
                                    cached.token.clone(),
                                    None,
                                ));
                            }
                        }
                    }
                }
            } else {
                // Token is valid and not near expiry
                return Ok(Credentials::new(
                    cached.username.clone(),
                    cached.token.clone(),
                    None,
                ));
            }
        }
        Err(e) => {
            return Err(anyhow!(
                "No valid authentication session found. Please log in first.\nDetails: {}",
                e
            ));
        }
    }
    
    // If we reach here, all token operations failed
    Err(anyhow!(
        "Authentication failed. Please log in again using a PAM-enabled service (e.g., login, sudo, etc.)"
    ))
}

// Fallback function for interactive authentication (kept for emergency use)
fn get_credentials_interactive() -> Result<Credentials> {
    println!("Interactive authentication fallback - this should not normally be needed.");
    println!("Consider logging in through a PAM-enabled service instead.");
    
    let username = Input::<String>::new()
        .with_prompt("Username")
        .interact_text()
        .context("Failed to read username")?;

    let mut password = dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .context("Failed to read password")?;

    // Get the result before clearing password
    let (token, user) = match RuleSet::login(&username, &password) {
        Ok((tok, usr)) => (tok, usr),
        Err(e) => {
            // Ensure password is cleared even on error
            password.zeroize();
            return Err(anyhow!("Authentication failed: {}", e));
        }
    };

    // Clear password from memory
    password.zeroize();

    Ok(Credentials::new(username, token, Some(user)))
}

// ----------------------------------------------------------------------------
// AppPolicy 
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
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
        paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":")
    }

    fn join_ports(ports: &HashSet<u16>) -> String {
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(":")
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
        let path_str = path.to_string_lossy();
        if path_str.len() > 4096 {
            return Err(anyhow!("Path too long: {}", path.display()));
        }

        // Check path doesn't contain unusual characters
        if path_str.contains('\0') {
            return Err(anyhow!("Path contains null bytes: {}", path.display()));
        }

        // Check for path traversal attempts
        if path_str.contains("..") {
            return Err(anyhow!(
                "Path contains potential traversal: {}",
                path.display()
            ));
        }

        Ok(())
    }

    // Create a policy from environment variables (for sandbox mode)
    fn from_env() -> Result<Self> {
        Ok(Self {
            ro_paths: Self::parse_paths_from_env("LL_FS_RO")?,
            rw_paths: Self::parse_paths_from_env("LL_FS_RW")?,
            tcp_bind: Self::parse_ports_from_env("LL_TCP_BIND")?,
            tcp_connect: Self::parse_ports_from_env("LL_TCP_CONNECT")?,
            allowed_ips: Self::parse_strings_from_env("LL_ALLOWED_IPS")?,
            allowed_domains: Self::parse_strings_from_env("LL_ALLOWED_DOMAINS")?,
        })
    }

    // Helper methods for parsing environment variables
    fn parse_paths_from_env(var: &str) -> Result<HashSet<PathBuf>> {
        let mut paths = HashSet::new();
        if let Ok(value) = env::var(var) {
            for path_str in value.split(':').filter(|s| !s.is_empty()) {
                let path = PathBuf::from(path_str);
                Self::validate_path(&path)?;
                paths.insert(path);
            }
        }
        Ok(paths)
    }

    fn parse_ports_from_env(var: &str) -> Result<HashSet<u16>> {
        let mut ports = HashSet::new();
        if let Ok(value) = env::var(var) {
            for port_str in value.split(':').filter(|s| !s.is_empty()) {
                match port_str.parse::<u16>() {
                    Ok(port) => {
                        ports.insert(port);
                    }
                    Err(e) => {
                        return Err(anyhow!("Invalid port in {}: {} - {}", var, port_str, e));
                    }
                }
            }
        }
        Ok(ports)
    }

    fn parse_strings_from_env(var: &str) -> Result<HashSet<String>> {
        let mut strings = HashSet::new();
        if let Ok(value) = env::var(var) {
            for s in value.split(':').filter(|s| !s.is_empty()) {
                strings.insert(s.to_string());
            }
        }
        Ok(strings)
    }
}

// ----------------------------------------------------------------------------
// Server communication 
// ----------------------------------------------------------------------------

fn verify_user_permissions(token: &str) -> Result<HashSet<String>> {
    let base_url = env::var("SERVER_URL").unwrap_or_else(|_| "https://127.0.0.1:8443".into());
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true) 
        .build()
        .context("Failed to build HTTPS client")?;

    let roles_url = format!("{}/auth/roles", base_url);
    let res = client
        .get(&roles_url)
        .bearer_auth(token)
        .send()
        .context("Failed to fetch user permissions")?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "Could not verify user permissions: {}",
            res.status()
        ));
    }

    let roles_info: RoleCheckResponse = res.json().context("Failed to parse roles response")?;

    Ok(roles_info.permissions.into_iter().collect())
}

// [Rest of the server communication functions remain unchanged from original]
fn update_policy_on_server(
    app: &str,
    policy: &AppPolicy,
    token: &str,
    permissions: &HashSet<String>,
) -> Result<()> {
    if !permissions.contains("manage_policies") {
        return Err(anyhow!("User does not have policy management permissions"));
    }

    let base_url = env::var("SERVER_URL").unwrap_or_else(|_| "https://127.0.0.1:8443".into()); 
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to build HTTPS client")?;
    
    // Create vectors from paths
    let ro_paths_vec: Vec<String> = policy
        .ro_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    
    let rw_paths_vec: Vec<String> = policy
        .rw_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    // First attempt to check if there's an existing pending request
    let check_url = format!("{}/policy/pending-requests", base_url);
    
    let res = client
        .get(&check_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .context("Failed to check for pending policy requests")?;
    
    let status = res.status();
    
    // If we can successfully retrieve pending requests
    let mut existing_request_id = None;
    if status.is_success() {
        let pending_requests: serde_json::Value = res.json()
            .context("Failed to parse pending requests response")?;
        
        // Check if there's already a pending request for this app and role
        if let Some(requests) = pending_requests.as_array() {
            for request in requests {
                if let (Some(req_app), Some(req_role)) = (
                    request.get("app_name").and_then(|v| v.as_str()),
                    request.get("role_id").and_then(|v| v.as_i64()),
                ) {
                    if req_app == app && req_role == 1 {
                        // Found an existing request
                        existing_request_id = request.get("id").and_then(|v| v.as_i64());
                        break;
                    }
                }
            }
        }
    }

    // Prepare the policy update payload
    let payload = serde_json::json!({
        "app_name": app.to_string(),
        "role_id": 1,
        "default_ro": AppPolicy::join_paths(&policy.ro_paths),
        "default_rw": AppPolicy::join_paths(&policy.rw_paths),
        "tcp_bind": AppPolicy::join_ports(&policy.tcp_bind),
        "tcp_connect": AppPolicy::join_ports(&policy.tcp_connect),
        "allowed_ips": AppPolicy::join_ips(&policy.allowed_ips),
        "allowed_domains": AppPolicy::join_domains(&policy.allowed_domains),
        "allowed_ro_paths": ro_paths_vec,
        "allowed_rw_paths": rw_paths_vec,
        "change_justification": "Automatically updated from sandboxer after access denial"
    });

    // If we found an existing request, try to update it
    let res = if let Some(id) = existing_request_id {
        let update_existing_url = format!("{}/policy/request/{}", base_url, id);
        client
            .put(&update_existing_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .context("Failed to update existing policy request")?
    } else {
        // Otherwise, create a new request
        let create_url = format!("{}/policy/request", base_url);
        client
            .post(&create_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .context("Failed to send policy update request")?
    };
    
    let status = res.status();
    
    if !status.is_success() {
        let error_text = res.text().unwrap_or_else(|_| "Unknown error".to_string());
        
        // Special handling for duplicate key constraint errors
        if error_text.contains("idx_unique_pending_requests") &&
           error_text.contains("existe déjà") {
            // Fall back to trying to delete the old request and create a new one
            println!("Detected duplicate request, attempting to delete existing request and create a new one...");
            
            // Try to find and delete any existing requests
            let delete_url = format!("{}/policy/delete-pending/{}/{}", base_url, app, 1);
            let delete_res = client
                .delete(&delete_url)
                .header("Authorization", format!("Bearer {}", token))
                .send();
                
            if let Ok(delete_res) = delete_res {
                if delete_res.status().is_success() {
                    println!("Successfully deleted existing pending request.");
                    
                    // Now try to create the request again
                    let create_url = format!("{}/policy/request", base_url);
                    let retry_res = client
                        .post(&create_url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/json")
                        .json(&payload)
                        .send();
                        
                    if let Ok(retry_res) = retry_res {
                        if retry_res.status().is_success() {
                            println!("Policy update request successfully submitted!");
                            println!("Note: Changes require admin approval before they take effect.");
                            return Ok(());
                        }
                    }
                }
            }
        }
        
        return Err(anyhow!(
            "Policy update request failed: {} - {}",
            status,
            error_text
        ));
    }

    println!("Policy update request successfully submitted!");
    println!("Note: Changes require admin approval before they take effect.");
    Ok(())
}

fn enforce_landlock(policy: &AppPolicy) -> Result<()> {
    let abi = ABI::V5;

    // Create the base ruleset with all necessary access types
    let base = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .context("Failed to handle filesystem access")?
        .handle_access(AccessNet::BindTcp)
        .context("Failed to handle TCP bind access")?
        .handle_access(AccessNet::ConnectTcp)
        .context("Failed to handle TCP connect access")?;

    let mut created = base.create().context("Failed to create Landlock ruleset")?;

    // Process read-only paths with improved error handling
    for path in &policy.ro_paths {
        if let Err(e) = AppPolicy::validate_path(path) {
            eprintln!("Warning: Skipping invalid read-only path: {}", e);
            continue;
        }

        match fs::canonicalize(path) {
            Ok(canonical_path) => {
                if let Ok(fd) = PathFd::new(canonical_path.as_os_str()) {
                    let rule = PathBeneath::new(fd, AccessFs::from_read(abi));
                    
                    // Important: Store the result in a temporary variable first
                    let result = created.add_rule(rule);
                    
                    // Then handle the result without using created again until reassigned
                    match result {
                        Ok(new_created) => created = new_created,
                        Err(e) => {
                            eprintln!(
                                "Warning: Failed to add read-only rule for {}: {}",
                                path.display(),
                                e
                            );
                            // We need to break here because created has been consumed
                            return Err(anyhow!("Failed to add ruleset rule: {}", e));
                        }
                    }
                } else {
                    eprintln!(
                        "Warning: Failed to open path {}",
                        canonical_path.display()
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: Failed to canonicalize path {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    // Apply the same pattern for read-write paths
    for path in &policy.rw_paths {
        if let Err(e) = AppPolicy::validate_path(path) {
            eprintln!("Warning: Skipping invalid read-write path: {}", e);
            continue;
        }

        if let Ok(canonical_path) = fs::canonicalize(path) {
            if let Ok(fd) = PathFd::new(canonical_path.as_os_str()) {
                let rule = PathBeneath::new(fd, AccessFs::from_all(abi));
                
                // Store result first
                let result = created.add_rule(rule);
                
                // Handle result safely
                match result {
                    Ok(new_created) => created = new_created,
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to add read-write rule for {}: {}",
                            path.display(),
                            e
                        );
                        return Err(anyhow!("Failed to add ruleset rule: {}", e));
                    }
                }
            } else {
                eprintln!(
                    "Warning: Failed to open path {}",
                    canonical_path.display()
                );
            }
        } else {
            eprintln!(
                "Warning: Failed to canonicalize path {}",
                path.display()
            );
        }
    }

    // TCP bind ports
    for port in &policy.tcp_bind {
        let rule = NetPort::new(*port, AccessNet::BindTcp);
        
        // Store result first
        let result = created.add_rule(rule);
        
        // Handle result safely
        match result {
            Ok(new_created) => created = new_created,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to add TCP bind rule for port {}: {}",
                    port, e
                );
                return Err(anyhow!("Failed to add TCP bind rule: {}", e));
            }
        }
    }

    // TCP connect ports
    for port in &policy.tcp_connect {
        let rule = NetPort::new(*port, AccessNet::ConnectTcp);
        
        // Store result first
        let result = created.add_rule(rule);
        
        // Handle result safely
        match result {
            Ok(new_created) => created = new_created,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to add TCP connect rule for port {}: {}",
                    port, e
                );
                return Err(anyhow!("Failed to add TCP connect rule: {}", e));
            }
        }
    }

    // Apply the ruleset
    created
        .restrict_self()
        .context("Failed to restrict process with Landlock rules")?;

    Ok(())
}

// ----------------------------------------------------------------------------
// Strace
// ----------------------------------------------------------------------------

fn run_strace(
    app_path: &Path,
    args: &[String],
    policy: &AppPolicy,
    prefix: &str,
) -> Result<(ExitStatus, TempDir)> {
    // Validate app path
    if let Err(e) = AppPolicy::validate_path(app_path) {
        return Err(anyhow!("Invalid application path: {}", e));
    }

    let tempdir = TempDir::new().context("Failed to create temporary directory")?;
    let log_prefix = tempdir.path().join(prefix);
    let log_path = log_prefix.to_string_lossy().to_string();

    let mut envs: Vec<(String, String)> = env::vars().collect();
    envs.push(("LL_FS_RO".into(), AppPolicy::join_paths(&policy.ro_paths)));
    envs.push(("LL_FS_RW".into(), AppPolicy::join_paths(&policy.rw_paths)));
    envs.push((
        "LL_TCP_BIND".into(),
        AppPolicy::join_ports(&policy.tcp_bind),
    ));
    envs.push((
        "LL_TCP_CONNECT".into(),
        AppPolicy::join_ports(&policy.tcp_connect),
    ));
    envs.push((
        "LL_ALLOWED_IPS".into(),
        AppPolicy::join_ips(&policy.allowed_ips),
    ));
    envs.push((
        "LL_ALLOWED_DOMAINS".into(),
        AppPolicy::join_domains(&policy.allowed_domains),
    ));

    let current_exe = env::current_exe().context("Failed to get current executable path")?;
    let strace_path = env::var("STRACE_PATH").unwrap_or_else(|_| "/usr/bin/strace".to_string());

    let status = Command::new(&strace_path)
        .args(&[
            "-ff",
            "-yy",
            "-e",
            "trace=file,process,openat,getdents,stat,connect,socket,bind",
        ])
        .arg("-o")
        .arg(&log_path)
        .arg(&current_exe)
        .arg("--sandbox")
        .arg(app_path)
        .args(args)
        .env_clear()
        .envs(envs)
        .status()
        .with_context(|| format!("Failed to execute strace at {}", strace_path))?;

    Ok((status, tempdir))
}

fn parse_denied_lines(dir: &Path, prefix: &str) -> Result<HashSet<String>> {
    // Improved regex patterns for better clarity and parsing
    let path_re =
        Regex::new(r#"openat\(.*?,\s*"([^"]+)"|stat\(.*?"([^"]+)"|getdents\(.*?,\s*"([^"]+)""#)
            .context("Failed to compile path regex")?;
    let net_re = Regex::new(r#"(connect|bind)\(.*?sin_port=htons\((\d+)\)"#)
        .context("Failed to compile network regex")?;
    let ip_re = Regex::new(r#"(connect|bind)\(.*?sin_addr=inet_addr\("([^"]+)"\)"#)
        .context("Failed to compile IP regex")?;
    let domain_re =
        Regex::new(r#"getaddrinfo\(.*?,\s*"([^"]+)"#).context("Failed to compile domain regex")?;

    let mut denials = HashSet::new();

    for entry in fs::read_dir(dir).context("Failed to read log directory")? {
        let entry = entry.context("Failed to read directory entry")?;
        if !entry.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }

        let file = match File::open(entry.path()) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "Warning: Could not open log file {}: {}",
                    entry.path().display(),
                    e
                );
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

            // Only process lines with access denied errors
            if !(line.contains("EACCES") || line.contains("EPERM")) {
                continue;
            }

            // Match filesystem path denials
            if let Some(cap) = path_re.captures(&line) {
                if let Some(p) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
                    let raw_path = PathBuf::from(p.as_str());

                    // Only canonicalize paths if possible, otherwise use the raw path
                    match fs::canonicalize(&raw_path) {
                        Ok(canonical_path) => {
                            denials.insert(canonical_path.to_string_lossy().to_string());
                        }
                        Err(_) => {
                            // If canonicalization fails, use the original path but mark it
                            denials.insert(format!("NONCANONICAL:{}", raw_path.to_string_lossy()));
                        }
                    }
                }
            }
            // Match network port denials
            else if let Some(cap) = net_re.captures(&line) {
                if let (Some(op), Some(port)) = (cap.get(1), cap.get(2)) {
                    // Validate port is a valid number before adding
                    if let Ok(port_num) = port.as_str().parse::<u16>() {
                        denials.insert(format!("tcp:{}:{}", op.as_str(), port_num));
                    } else {
                        eprintln!(
                            "Warning: Invalid port number in denial log: {}",
                            port.as_str()
                        );
                    }
                }
            }
            // Match IP address denials
            else if let Some(cap) = ip_re.captures(&line) {
                if let Some(ip) = cap.get(2) {
                    denials.insert(format!("ip:{}", ip.as_str()));
                }
            }
            // Match domain name denials
            else if let Some(cap) = domain_re.captures(&line) {
                if let Some(domain) = cap.get(1) {
                    denials.insert(format!("domain:{}", domain.as_str()));
                }
            }
        }
    }

    Ok(denials)
}

fn process_denials(
    denials: HashSet<String>,
    policy: &mut AppPolicy,
    permissions: &HashSet<String>,
) -> Result<bool> {
    let mut updated = false;
    let can_update = permissions.contains("manage_policies");

    if !can_update {
        println!("User does not have permission to manage policies. Denials will be logged only.");
        for denial in &denials {
            println!("  - Denied: {}", denial);
        }
        return Ok(false);
    }

    for entry in denials {
        if entry.starts_with("tcp:") {
            // TCP port handling
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
                            println!(
                                "Warning: Maximum TCP connect ports ({}) reached",
                                MAX_TCP_CONNECT_PORTS
                            );
                            continue;
                        }
                        policy.tcp_connect.insert(port);
                        updated = true;
                    } else if op == "bind" {
                        if policy.tcp_bind.len() >= MAX_TCP_BIND_PORTS {
                            println!(
                                "Warning: Maximum TCP bind ports ({}) reached",
                                MAX_TCP_BIND_PORTS
                            );
                            continue;
                        }
                        policy.tcp_bind.insert(port);
                        updated = true;
                    }
                }
            }
        } else if entry.starts_with("ip:") {
            // IP address handling
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
            // Domain handling
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
        } else {
            // Handle paths
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
                        eprintln!(
                            "Warning: Still unable to canonicalize path {}: {}",
                            path.display(),
                            e
                        );
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
                .with_prompt(format!(
                    "Denied path: {}. Allow as?",
                    canonical_path.display()
                ))
                .items(choices)
                .default(2)
                .interact()?;

            match selection {
                0 => {
                    // Check limits before adding
                    if policy.ro_paths.len() >= MAX_RO_PATHS {
                        println!(
                            "Warning: Maximum number of read-only paths ({}) reached.",
                            MAX_RO_PATHS
                        );
                        continue;
                    }
                    policy.ro_paths.insert(canonical_path);
                    updated = true;
                }
                1 => {
                    // Check limits before adding
                    if policy.rw_paths.len() >= MAX_RW_PATHS {
                        println!(
                            "Warning: Maximum number of read-write paths ({}) reached.",
                            MAX_RW_PATHS
                        );
                        continue;
                    }
                    policy.rw_paths.insert(canonical_path);
                    updated = true;
                }
                _ => {}
            };
        }
    }

    Ok(updated)
}

// ----------------------------------------------------------------------------
// Main entrypoint (updated to use PAM token integration)
// ----------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Special --sandbox execution for the strace'd command
    if args.len() >= 2 && args[1] == "--sandbox" {
        return run_sandbox();
    }

    // Validate command line usage
    if args.len() < 2 {
        return Err(anyhow!("Usage: {} <APP> [ARGS...]", args[0]));
    }

    // Check if we have --interactive-auth flag for fallback
    let use_interactive = args.contains(&"--interactive-auth".to_string());

    // Get app path and args
    let app = &args[1];
    let app_args = &args[2..];

    // Validate app path
    let app_path = Path::new(app);
    if let Err(e) = AppPolicy::validate_path(app_path) {
        return Err(anyhow!("Invalid application path: {}", e));
    }

    // Get credentials from PAM cache or fallback to interactive
    let credentials = if use_interactive {
        get_credentials_interactive().context("Interactive authentication failed")?
    } else {
        match get_credentials() {
            Ok(creds) => creds,
            Err(e) => {
                eprintln!("Failed to retrieve cached authentication: {}", e);
                eprintln!("Hint: Use --interactive-auth flag for manual authentication");
                return Err(e);
            }
        }
    };

    println!("Authentication successful! User: {}", credentials.username);

    // Verify user permissions
    let permissions =
        verify_user_permissions(&credentials.token).context("Failed to verify user permissions")?;

    // Retrieve policy from server
    let ruleset = RuleSet::fetch_for_app(app, &credentials.token)
        .context("Failed to fetch policy from server")?;
    let mut policy = AppPolicy::from(ruleset);
    let original_policy = policy.clone();

    // First run with strace to capture denials
    println!("Running application with current policy...");
    let (status, tempdir) = run_strace(app_path, app_args, &policy, "sandbox_log")
        .context("Failed to run application with strace")?;

    // Parse denial logs
    let denials =
        parse_denied_lines(tempdir.path(), "sandbox_log").context("Failed to parse denial logs")?;

    // Log denials if any
    if !denials.is_empty() {
        println!("Detected {} access denials", denials.len());

        for denial in &denials {
            let resource_type = if denial.starts_with("tcp:")
                || denial.starts_with("ip:")
                || denial.starts_with("domain:")
            {
                "network"
            } else {
                "filesystem"
            };

            if let Err(e) = log_denial_event(app, denial, resource_type, &credentials.token) {
                eprintln!("Warning: Failed to log denial event: {}", e);
            }
        }

        // Process denials and update policy if user has permission
        let updated = process_denials(denials.clone(), &mut policy, &permissions)?;

        // Update policy on server if changes were made
        if updated {
            match update_policy_on_server(app, &policy, &credentials.token, &permissions) {
                Ok(_) => {
                    println!("Your policy update request has been submitted and is pending approval.");
                    println!("Until approved, the current policy remains in effect.");
                }
                Err(e) => {
                    eprintln!("Warning: Failed to upload policy update: {}", e);
                    println!(
                        "Policy was updated locally but changes were not saved on the server."
                    );
                }
            }

            // Offer to rerun with current (approved) policy
            let rerun = dialoguer::Confirm::new()
                .with_prompt("Would you like to rerun the application with the current (approved) policy?")
                .default(true)
                .interact()
                .unwrap_or(false);

            if rerun {
                println!("Rerunning application with approved policy...");
                match run_strace(app_path, app_args, &original_policy, "rerun_log") {
                    Ok((status, _)) => {
                        println!(
                            "Application rerun completed with exit code: {}",
                            status.code().unwrap_or(-1)
                        );
                    }
                    Err(e) => {
                        eprintln!("Error during rerun: {}", e);
                    }
                }
            }
        }
    } else if !status.success() {
        println!(
            "Application exited with code: {}",
            status.code().unwrap_or(-1)
        );
        println!("No access denial events were detected. The issue may be application-specific.");
    } else {
        println!("Application ran successfully with the current policy.");
    }

    Ok(())
}

// Add this function to your sandboxer_db.rs file

fn run_sandbox() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    // Skip the first two args (program name and "--sandbox")
    if args.len() < 3 {
        return Err(anyhow!("Usage: {} --sandbox <APP> [ARGS...]", args[0]));
    }
    
    let app_path = &args[2];
    let app_args = &args[3..];
    
    // Load policy from environment variables (set by parent strace process)
    let policy = AppPolicy::from_env()
        .context("Failed to load policy from environment variables")?;
    
    // Apply Landlock restrictions based on the policy
    enforce_landlock(&policy)
        .context("Failed to apply Landlock restrictions")?;
    
    // Execute the target application
    let status = Command::new(app_path)
        .args(app_args)
        .status()
        .with_context(|| format!("Failed to execute application: {}", app_path))?;
    
    // Exit with the same code as the target application
    std::process::exit(status.code().unwrap_or(1));
}
