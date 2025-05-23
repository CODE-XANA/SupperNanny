use anyhow::{anyhow, Context, Result};
use bcrypt::verify;
use dialoguer::{Confirm, Input, Password, Select};
use dotenv::dotenv;
use hostname::get as get_hostname_raw;
use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use once_cell::sync::Lazy;
use postgres::{Config, NoTls};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;
use tempfile::TempDir;

// -----------------------------------------------------------------------
// Corrected helpers (recommended changes)
// -----------------------------------------------------------------------

/// Stricter executable path validation
fn validate_executable_path(path_str: &str) -> Result<std::path::PathBuf> {
    let path = PathBuf::from(path_str);

    // Ensure the path actually exists
    if !path.exists() {
        return Err(anyhow!("Executable path does not exist: {}", path_str));
    }

    // Use symlink_metadata so we can check for symlinks
    let meta = fs::symlink_metadata(&path)
        .with_context(|| format!("Failed to read metadata for '{}'", path_str))?;

    // Reject symlinks to prevent potential path traversal
    if meta.file_type().is_symlink() {
        return Err(anyhow!("Symlinks are not allowed: {}", path_str));
    }

    if !meta.is_file() {
        return Err(anyhow!("Path is not a regular file: {}", path_str));
    }

    // On Unix, do extra permission checks
    #[cfg(unix)]
    {
        let perms = meta.permissions();
        let mode = perms.mode();

        // Ensure the file is executable by at least the owner (0o111).
        if (mode & 0o111) == 0 {
            return Err(anyhow!("File is not executable: {}", path_str));
        }

        // Additional security: reject world-writable executables
        if (mode & 0o002) != 0 {
            return Err(anyhow!("World-writable executables are not allowed: {}", path_str));
        }
    }

    // Use canonicalize for a fully qualified path
    fs::canonicalize(&path)
        .map_err(|e| anyhow!("Failed to canonicalize path '{}': {}", path_str, e))
}

/// Example log path sanitizer
fn sanitize_log_path(path: &Path) -> String {
    // For illustration, assume we have some "home" path:
    // You can replace this with any actual logic for retrieving a home dir
    let home_dir = PathBuf::from("/home/unknown"); 
    let home_str = home_dir.to_string_lossy();      // This is a Cow<str>
    let path_str = path.to_string_lossy();          // Also a Cow<str>

    // Convert the Cow<str> to &str before calling replace
    path_str.replace(home_str.as_ref(), "<HOME>")
}

/// Safely parse environment variables into a set of canonical paths
fn parse_env_paths(var_name: &str) -> HashSet<PathBuf> {
    env::var(var_name)
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .filter_map(|path_str| {
            // Try canonicalizing; skip any invalid or non-existent paths
            fs::canonicalize(path_str).ok()
        })
        .collect()
}

/// Safely parse environment variables into ports, ignoring any invalid or privileged (<1024) ports
fn parse_env_ports(var_name: &str) -> HashSet<u16> {
    env::var(var_name)
        .unwrap_or_default()
        .split(':')
        .filter_map(|s| s.parse::<u16>().ok())
        .filter(|&port| port >= 1024) // example: skip <1024 if you like
        .collect()
}

/// Create a database connection pool with environment variables
fn create_db_pool() -> Result<Pool<PostgresConnectionManager<NoTls>>> {
    let host = env::var("DB_HOST")
        .context("DB_HOST environment variable must be set")?;
    let port = env::var("DB_PORT")
        .context("DB_PORT environment variable must be set")?
        .parse::<u16>()
        .context("Invalid DB_PORT")?;
    let user = env::var("DB_USER")
        .context("DB_USER environment variable must be set")?;
    let pass = env::var("DB_PASS")
        .context("DB_PASS environment variable must be set")?;
    let dbname = env::var("DB_NAME")
        .context("DB_NAME environment variable must be set")?;

    let mut pg_config = Config::new();
    pg_config
        .host(&host)
        .port(port)
        .user(&user)
        .password(&pass)
        .dbname(&dbname)
        .connect_timeout(Duration::from_secs(10));

    let manager = PostgresConnectionManager::new(pg_config, NoTls);

    Pool::builder()
        .max_size(10)
        .min_idle(Some(5))
        .connection_timeout(Duration::from_secs(30))
        .build(manager)
        .context("Failed to create database connection pool")
}

// -----------------------------------------------------------------------
// Main Production code (updated to use create_db_pool for the static POOL)
// -----------------------------------------------------------------------

#[derive(Debug)]
struct AppPolicy {
    ro_paths: HashSet<PathBuf>,
    rw_paths: HashSet<PathBuf>,
    tcp_bind: HashSet<u16>,
    tcp_connect: HashSet<u16>,
    allowed_ips: HashSet<String>,
    allowed_domains: HashSet<String>,
}

#[derive(Debug)]
struct User {
    user_id: i32,
    #[allow(dead_code)]
    username: String,
}

// Our global static pool, created via `create_db_pool`
static POOL: Lazy<Pool<PostgresConnectionManager<NoTls>>> = Lazy::new(|| {
    dotenv().ok();
    create_db_pool().expect("Failed to create database pool")
});

pub fn get_db_conn() -> Result<PooledConnection<PostgresConnectionManager<NoTls>>> {
    POOL.get().context("Failed to get DB connection from pool")
}

// -----------------------------------------------------------------------
// RBAC Functions
// -----------------------------------------------------------------------

fn authenticate_user(username: &str, password: &str) -> Result<User> {
    let mut conn = get_db_conn().context("Failed to get DB connection for authentication")?;

    let row = conn
        .query_opt(
            "SELECT user_id, password_hash FROM users WHERE username = $1",
            &[&username],
        )
        .context("Authentication query failed")?
        .ok_or_else(|| anyhow!("User not found"))?;

    let stored_hash: String = row.get(1);
    if verify(password, &stored_hash).map_err(|e| anyhow!("Password verification failed: {}", e))? {
        Ok(User {
            user_id: row.get(0),
            username: username.to_string(),
        })
    } else {
        Err(anyhow!("Invalid credentials"))
    }
}

fn has_permission(user_id: i32, permission: &str) -> Result<bool> {
    let mut conn = get_db_conn().context("Failed to get DB connection for permission check")?;
    let count: i64 = conn
        .query_one(
            r#"
        SELECT COUNT(*) FROM role_permissions
        WHERE role_id IN (
            SELECT role_id FROM user_roles WHERE user_id = $1
        )
        AND permission_id = (
            SELECT permission_id FROM permissions WHERE permission_name = $2
        )
        "#,
            &[&user_id, &permission],
        )?
        .get(0);

    Ok(count > 0)
}

// -----------------------------------------------------------------------
// DB Functions
// -----------------------------------------------------------------------

fn parse_paths(paths: String) -> HashSet<PathBuf> {
    paths
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_ports(ports: String) -> HashSet<u16> {
    ports
        .split(':')
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn parse_ips(ips: String) -> HashSet<String> {
    ips
        .split(':')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_domains(domains: String) -> HashSet<String> {
    domains
        .split(':')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

impl AppPolicy {
    fn default_policy_for_role(role_id: i32) -> Result<Self> {
        let mut conn =
            get_db_conn().context("Failed to get DB connection for fetching default policy")?;

        let query = "
            SELECT default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
            FROM default_policies
            WHERE role_id = $1
        ";

        let row = conn
            .query_one(query, &[&role_id])
            .context("Failed to fetch default policy from database")?;

        let ro_paths = parse_paths(row.get("default_ro"));
        let rw_paths = parse_paths(row.get("default_rw"));
        let tcp_bind = parse_ports(row.get("tcp_bind"));
        let tcp_connect = parse_ports(row.get("tcp_connect"));
        let allowed_ips = parse_ips(row.get("allowed_ips"));
        let allowed_domains = parse_domains(row.get("allowed_domains"));

        Ok(Self {
            ro_paths,
            rw_paths,
            tcp_bind,
            tcp_connect,
            allowed_ips,
            allowed_domains,
        })
    }

    fn join_ips(ips: &HashSet<String>) -> String {
        ips.iter().cloned().collect::<Vec<_>>().join(":")
    }

    fn join_domains(domains: &HashSet<String>) -> String {
        domains.iter().cloned().collect::<Vec<_>>().join(":")
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

    fn contains_path(&self, path: &Path) -> bool {
        self.ro_paths.contains(path) || self.rw_paths.contains(path)
    }
}

fn fetch_policy_from_db(app: &str, user: &User) -> Result<AppPolicy> {
    let mut client = get_db_conn().context("Failed to get DB connection for policy fetch")?;

    // Get user's roles (assuming single role for simplicity)
    let roles: Vec<i32> = client
        .query(
            "SELECT r.role_id FROM roles r
         JOIN user_roles ur ON r.role_id = ur.role_id
         WHERE ur.user_id = $1",
            &[&user.user_id],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect();

    // Try each role until we find a policy
    for &role_id in &roles {
        let query = r#"
            SELECT default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
            FROM app_policy
            WHERE app_name = $1 AND role_id = $2
        "#;

        if let Some(row) = client.query_opt(query, &[&app, &role_id])? {
            let ro_paths = parse_paths(row.get("default_ro"));
            let rw_paths = parse_paths(row.get("default_rw"));
            let tcp_bind = parse_ports(row.get("tcp_bind"));
            let tcp_connect = parse_ports(row.get("tcp_connect"));
            let allowed_ips = parse_ips(row.get("allowed_ips"));
            let allowed_domains = parse_domains(row.get("allowed_domains"));

            return Ok(AppPolicy {
                ro_paths,
                rw_paths,
                tcp_bind,
                tcp_connect,
                allowed_ips,
                allowed_domains,
            });
        }
    }

    // Fallback to default policy for the first role (or handle no role differently)
    let default_role_id = roles.first().copied().unwrap_or(0);
    AppPolicy::default_policy_for_role(default_role_id)
}

fn update_policy_in_db(app: &str, policy: &AppPolicy, user: &User) -> Result<()> {
    if !has_permission(user.user_id, "manage_policies")? {
        return Err(anyhow!("Insufficient permissions to modify policies"));
    }

    let mut conn = get_db_conn().context("Failed to get DB connection for policy update")?;
    let mut tx = conn.transaction().context("Failed to start transaction")?;

    // Retrieve the user's role (assume one primary role per user)
    let role_id: i32 = tx
        .query_one(
            "SELECT r.role_id FROM roles r
         JOIN user_roles ur ON r.role_id = ur.role_id
         WHERE ur.user_id = $1 LIMIT 1",
            &[&user.user_id],
        )?
        .get(0);

    let sql = r#"
    INSERT INTO app_policy
    (app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    ON CONFLICT (app_name, role_id) DO UPDATE SET
        default_ro = EXCLUDED.default_ro,
        default_rw = EXCLUDED.default_rw,
        tcp_bind = EXCLUDED.tcp_bind,
        tcp_connect = EXCLUDED.tcp_connect,
        allowed_ips = EXCLUDED.allowed_ips,
        allowed_domains = EXCLUDED.allowed_domains,
        updated_at = NOW()
    "#;

    tx.execute(
        sql,
        &[
            &app,
            &role_id,
            &AppPolicy::join_paths(&policy.ro_paths),
            &AppPolicy::join_paths(&policy.rw_paths),
            &AppPolicy::join_ports(&policy.tcp_bind),
            &AppPolicy::join_ports(&policy.tcp_connect),
            &AppPolicy::join_ips(&policy.allowed_ips),
            &AppPolicy::join_domains(&policy.allowed_domains),
        ],
    )
    .with_context(|| {
        format!(
            "Failed to update policy for app '{}' and role_id '{}'",
            app, role_id
        )
    })?;

    tx.commit().context("Failed to commit policy update")?;

    log_event(
        user.user_id,
        app,
        Path::new("policy"),
        "policy_update",
        "success",
    )?;

    Ok(())
}

// -----------------------------------------------------------------------
// Logging
// -----------------------------------------------------------------------

fn get_hostname() -> String {
    get_hostname_raw()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .into_owned()
}

fn log_event(user_id: i32, app: &str, path: &Path, operation: &str, result: &str) -> Result<()> {
    let hostname = get_hostname();

    // Use sanitized path for logging
    let denied_path = sanitize_log_path(path);

    let mut conn = get_db_conn().context("Failed to get DB connection for logging")?;
    let mut tx = conn
        .transaction()
        .context("Failed to start logging transaction")?;

    let sql = r#"
        INSERT INTO sandbox_events
        (hostname, app_name, denied_path, operation, result, user_id)
        VALUES ($1, $2, $3, $4, $5, $6)
    "#;

    tx.execute(
        sql,
        &[&hostname, &app, &denied_path, &operation, &result, &user_id],
    )
    .with_context(|| {
        format!(
            "Failed to log event: app={}, path={}, op={}",
            app, denied_path, operation
        )
    })?;

    tx.commit().context("Failed to commit log entry")?;
    Ok(())
}

// -----------------------------------------------------------------------
// Landlock Enforcement
// -----------------------------------------------------------------------

fn enforce_landlock(policy: &AppPolicy) -> Result<()> {
    let abi = ABI::V5;
    let base = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::BindTcp)?
        .handle_access(AccessNet::ConnectTcp)?;

    let mut created = base
        .create()
        .context("Failed to create Landlock ruleset (check if Landlock is supported)")?;

    // Add read-only paths
    for path in &policy.ro_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str()).with_context(|| {
                format!("Could not create PathFd for '{}'", canonical_path.display())
            })?;
            let rule = PathBeneath::new(fd, AccessFs::from_read(abi));
            created = created.add_rule(rule).with_context(|| {
                format!(
                    "Could not add read-only rule for '{}'",
                    canonical_path.display()
                )
            })?;
        }
    }

    // Add read-write paths
    for path in &policy.rw_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str()).with_context(|| {
                format!("Could not create PathFd for '{}'", canonical_path.display())
            })?;
            let rule = PathBeneath::new(fd, AccessFs::from_all(abi));
            created = created.add_rule(rule).with_context(|| {
                format!(
                    "Could not add read/write rule for '{}'",
                    canonical_path.display()
                )
            })?;
        }
    }

    // Add TCP rules
    for port in &policy.tcp_bind {
        created = created
            .add_rule(NetPort::new(*port, AccessNet::BindTcp))
            .with_context(|| format!("Could not add TCP bind rule for port {}", port))?;
    }
    for port in &policy.tcp_connect {
        created = created
            .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
            .with_context(|| format!("Could not add TCP connect rule for port {}", port))?;
    }

    let status = created
        .restrict_self()
        .context("Failed to restrict self with Landlock ruleset")?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(anyhow!("Landlock is not supported by the running kernel"));
    }

    println!("Landlock ruleset enforced successfully.");
    Ok(())
}

// -----------------------------------------------------------------------
// Running in "sandbox" mode (strace instrumentation) + denial processing
// -----------------------------------------------------------------------

fn run_sandbox_run_mode(
    app_path: &Path,
    app_args: &[String],
    policy: &AppPolicy,
    log_file_prefix: &str,
) -> Result<(ExitStatus, TempDir)> {
    let tempdir = TempDir::new().context("Failed to create temporary directory for strace logs")?;
    let log_prefix_path = tempdir.path().join(log_file_prefix);
    let log_prefix_str = log_prefix_path.to_string_lossy().to_string();

    // Prepare environment variables for the child
    // (using safer parse_env_* for examples, but we still join our sets)
    let mut child_env = env::vars().collect::<Vec<(String, String)>>();

    child_env.push(("LL_FS_RO".into(), AppPolicy::join_paths(&policy.ro_paths)));
    child_env.push(("LL_FS_RW".into(), AppPolicy::join_paths(&policy.rw_paths)));
    child_env.push(("LL_TCP_BIND".into(), AppPolicy::join_ports(&policy.tcp_bind)));
    child_env.push(("LL_TCP_CONNECT".into(), AppPolicy::join_ports(&policy.tcp_connect)));
    child_env.push(("LL_ALLOWED_IPS".into(), AppPolicy::join_ips(&policy.allowed_ips)));
    child_env.push(("LL_ALLOWED_DOMAINS".into(), AppPolicy::join_domains(&policy.allowed_domains)));

    let current_exe =
        env::current_exe().context("Failed to get current executable for strace invocation")?;

    let status = Command::new("strace")
        .args(&[
            "-ff",
            "-yy",
            "-e",
            "trace=file,process,openat,getdents,stat,connect,socket,bind",
        ])
        .arg("-o")
        .arg(&log_prefix_str)
        // We'll re-invoke our *own* binary with `--sandbox` so that `sandbox_main` is used.
        .arg(&current_exe)
        .arg("--sandbox")
        .arg(app_path)
        .args(app_args)
        .env_clear()
        .envs(child_env)
        .status()
        .with_context(|| format!("Failed to spawn strace for '{}'", app_path.display()))?;

    Ok((status, tempdir))
}

/// Parse strace output for EACCES or EPERM lines, collecting either file paths or "tcp:<port>"
fn parse_denied_lines(log_dir: &Path, prefix: &str) -> Result<HashSet<String>> {
    let path_re = Regex::new(
        r#"(?x)
        ^
        (?:
           openat\(.*?,\s*"([^"]+)" |
           (?:open|stat|execve|access|readlink)\("([^"]+)" |
           getdents(?:64)?\(.*?,\s*"([^"]+)"
        )
        "#,
    )?;

    let net_re = Regex::new(
        r#"(?x)
        ^
        (?:
           (?:connect|bind)\(.*?sin_port=htons\((\d+)\)
        )
        "#,
    )?;

    let mut denials = HashSet::new();

    let entries = fs::read_dir(log_dir)
        .with_context(|| format!("Failed to read directory '{}'", log_dir.display()))?;
    for entry_result in entries {
        let entry = entry_result
            .with_context(|| format!("Error iterating over directory '{}'", log_dir.display()))?;
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.starts_with(prefix) {
            continue;
        }

        let file = fs::File::open(entry.path()).with_context(|| {
            format!("Failed to open strace log file '{}'", entry.path().display())
        })?;

        for line_result in BufReader::new(file).lines() {
            let line = line_result
                .with_context(|| format!("Failed to read line in '{}'", entry.path().display()))?;

            if !(line.contains("EACCES") || line.contains("EPERM")) {
                continue;
            }

            // Try matching a file-based syscall
            if let Some(caps) = path_re.captures(&line) {
                let path_str = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .or_else(|| caps.get(3))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                if !path_str.is_empty() {
                    denials.insert(path_str.to_string());
                    continue;
                }
            }

            // If not file-based, match network-based syscalls
            if let Some(caps) = net_re.captures(&line) {
                if let Some(port_match) = caps.get(1) {
                    let port = port_match.as_str();
                    denials.insert(format!("tcp:{}", port));
                    continue;
                }
            }
        }
    }

    Ok(denials)
}

fn process_denials(
    log_dir: &Path,
    prefix: &str,
    policy: &mut AppPolicy,
    app: &str,
    user: &User,
) -> Result<bool> {
    let denied_entries = parse_denied_lines(log_dir, prefix)?;

    let mut updated = false;
    let can_manage = has_permission(user.user_id, "manage_policies")?;

    for entry in denied_entries {
        if entry.starts_with("tcp:") {
            let port_str = entry.trim_start_matches("tcp:");
            if let Ok(port) = port_str.parse::<u16>() {
                if policy.tcp_bind.contains(&port) || policy.tcp_connect.contains(&port) {
                    continue;
                }
                if can_manage {
                    let choices = &["Allow TCP Bind", "Allow TCP Connect", "Deny"];
                    let selection = Select::new()
                        .with_prompt(format!(
                            "TCP connection denied for port {}. Allow as:",
                            port
                        ))
                        .items(choices)
                        .default(2)
                        .interact()?;
                    match selection {
                        0 => {
                            policy.tcp_bind.insert(port);
                            log_event(
                                user.user_id,
                                app,
                                Path::new(&format!("tcp:{}", port)),
                                "syscall",
                                "granted_tcp_bind",
                            )?;
                            updated = true;
                        }
                        1 => {
                            policy.tcp_connect.insert(port);
                            log_event(
                                user.user_id,
                                app,
                                Path::new(&format!("tcp:{}", port)),
                                "syscall",
                                "granted_tcp_connect",
                            )?;
                            updated = true;
                        }
                        _ => {
                            log_event(
                                user.user_id,
                                app,
                                Path::new(&format!("tcp:{}", port)),
                                "syscall",
                                "denied",
                            )?;
                        }
                    }
                } else {
                    log_event(
                        user.user_id,
                        app,
                        Path::new(&format!("tcp:{}", port)),
                        "syscall",
                        "denied",
                    )?;
                }
            }
        } else {
            let path = PathBuf::from(&entry);
            if policy.contains_path(&path) {
                continue;
            }
            let final_path = fs::canonicalize(&path).unwrap_or(path.clone());
            if can_manage {
                let choices = &["Read-Only", "Read-Write", "Deny"];
                let selection = Select::new()
                    .with_prompt(format!(
                        "Access denied for {}. Allow as:",
                        final_path.display()
                    ))
                    .items(choices)
                    .default(2)
                    .interact()?;
                match selection {
                    0 => {
                        policy.ro_paths.insert(final_path.clone());
                        log_event(user.user_id, app, &final_path, "syscall", "granted_ro")?;
                        updated = true;
                    }
                    1 => {
                        policy.rw_paths.insert(final_path.clone());
                        log_event(user.user_id, app, &final_path, "syscall", "granted_rw")?;
                        updated = true;
                    }
                    _ => {
                        log_event(user.user_id, app, &final_path, "syscall", "denied")?;
                    }
                }
            } else {
                log_event(user.user_id, app, &final_path, "syscall", "denied")?;
            }
        }
    }

    // Return true only if we updated AND we have permission
    Ok(updated && can_manage)
}

// -----------------------------------------------------------------------
// management_flow and sandbox_main
// -----------------------------------------------------------------------

fn management_flow() -> Result<()> {
    // Prompt for username
    let username = Input::<String>::new()
        .with_prompt("Username")
        .interact()
        .context("Failed to read username")?;

    // Prompt for password
    let password = Password::new()
        .with_prompt("Password")
        .interact()
        .context("Failed to read password")?;

    // Attempt authentication
    let user = authenticate_user(&username, &password).context("Authentication failed")?;

    // Check whether the user can execute
    if !has_permission(user.user_id, "execute_apps")? {
        return Err(anyhow!("Insufficient permissions to execute applications"));
    }

    // Parse command-line args for the target application
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(anyhow!("Usage: {} <APP> [ARGS...]", args[0]));
    }
    let raw_app = &args[1];
    let app_args = &args[2..];

    // -------------------------------------------------------------------
    // **Validate the executable path**:
    // This ensures that 'raw_app' refers to a valid, non-symlink,
    // executable file (and not world-writable, if on Unix).
    // -------------------------------------------------------------------
    let validated_path = validate_executable_path(raw_app)?;
    println!("Using validated executable path: {}", validated_path.display());

    // Fetch the policy for the specified application
    let mut policy = fetch_policy_from_db(raw_app, &user)
        .with_context(|| format!("Failed to fetch policy for '{}'", raw_app))?;

    // First run with strace
    let first_prefix = "sandboxer_first.log";
    let (first_status, first_tempdir) =
        run_sandbox_run_mode(&validated_path, app_args, &policy, first_prefix)?;

    let has_denials = !parse_denied_lines(first_tempdir.path(), first_prefix)?.is_empty();
    let needs_processing = !first_status.success() || has_denials;

    if needs_processing {
        println!("Processing denials...");
        let changed = process_denials(
            first_tempdir.path(),
            first_prefix,
            &mut policy,
            raw_app,
            &user,
        )?;

        if changed {
            update_policy_in_db(raw_app, &policy, &user)?;

            let do_second_run = Confirm::new()
                .with_prompt("Would you like to run the application again with the updated policy?")
                .default(true)
                .interact()?;

            if do_second_run {
                let second_prefix = "sandboxer_second.log";
                let (second_status, second_tempdir) =
                    run_sandbox_run_mode(&validated_path, app_args, &policy, second_prefix)?;

                let second_denials = parse_denied_lines(second_tempdir.path(), second_prefix)?;

                if second_denials.is_empty() && second_status.success() {
                    println!("Second run successful. No denied operations.");
                } else {
                    println!("Denied operations still detected. Further updates may be needed.");
                }
            } else {
                println!("Exiting without second run.");
            }
        } else {
            // No changes were made
            if has_permission(user.user_id, "manage_policies")? {
                println!("No policy changes made. Skipping second run.");
            } else {
                println!("Insufficient permissions for policy updates. Skipping second run.");
            }
        }
    } else {
        println!("Program executed successfully under sandbox.");
    }

    Ok(())
}

/// This is the entry point that actually enforces Landlock rules and then runs the specified command.
fn sandbox_main() -> ! {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} --sandbox <APP> [ARGS...]", args[0]);
        std::process::exit(1);
    }

    let cmd = &args[2];
    let cmd_args = &args[3..];

    // Create a policy object from environment variables (instead of DB),
    // so that this child process knows what it can do.
    let policy = AppPolicy {
        ro_paths: parse_env_paths("LL_FS_RO"),
        rw_paths: parse_env_paths("LL_FS_RW"),
        tcp_bind: parse_env_ports("LL_TCP_BIND"),
        tcp_connect: parse_env_ports("LL_TCP_CONNECT"),
        allowed_ips: env::var("LL_ALLOWED_IPS")
            .unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        allowed_domains: env::var("LL_ALLOWED_DOMAINS")
            .unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
    };

    // Actually enforce Landlock
    if let Err(e) = enforce_landlock(&policy) {
        eprintln!("Failed to enforce Landlock rules: {}", e);
        std::process::exit(1);
    }

    // Finally, execute the real command inside this restricted environment
    match Command::new(cmd).args(cmd_args).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("Failed to execute '{}': {}", cmd, e);
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "--sandbox" {
        sandbox_main();
    } else {
        if let Err(e) = management_flow() {
            eprintln!("Error in management flow: {:?}", e);
            std::process::exit(1);
        }
    }
}

// -----------------------------------------------------------------------
// In your main code, add a testing-only default_policy constructor:
// -----------------------------------------------------------------------
impl AppPolicy {
    /// A simple helper returning a hardcoded policy for tests.
    #[cfg(test)]
    fn default_policy() -> Self {
        AppPolicy {
            ro_paths: vec![PathBuf::from("/bin"), PathBuf::from("/etc")]
                .into_iter()
                .collect(),
            rw_paths: vec![PathBuf::from("/tmp")].into_iter().collect(),
            tcp_bind: HashSet::new(),
            tcp_connect: HashSet::new(),
            allowed_ips: HashSet::new(),
            allowed_domains: HashSet::new(),
        }
    }
}

// -----------------------------------------------------------------------
// Test code begins here.
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use anyhow::Result; // if you're using anyhow for test returns

    /// Test a default in-memory policy. Adjust the contents as you see fit.
    #[test]
    fn test_default_policy() {
        let policy = AppPolicy::default_policy();
        assert!(policy.ro_paths.contains(Path::new("/bin")));
        assert!(policy.ro_paths.contains(Path::new("/etc")));
        assert!(policy.rw_paths.contains(Path::new("/tmp")));
    }

    #[test]
    fn test_join_paths_and_ports() {
        let mut policy = AppPolicy::default_policy();

        // Insert a read-only path, then check the joined result
        policy.ro_paths.insert(PathBuf::from("/home"));
        let ro_joined = AppPolicy::join_paths(&policy.ro_paths);
        assert!(ro_joined.contains("/home"));

        // Insert a TCP bind port, then check the joined result
        policy.tcp_bind.insert(1234);
        let bind_joined = AppPolicy::join_ports(&policy.tcp_bind);
        assert!(bind_joined.contains("1234"));
    }

    /// Example DB interaction test. Make sure your DB and test data exist.
    #[test]
    fn test_db_interaction() -> Result<()> {
        let app_name = "test_db_interaction_app";

        // Create a test policy with a few entries
        let mut policy = AppPolicy::default_policy();
        policy.ro_paths.insert(PathBuf::from("/test/db/path"));
        policy.rw_paths.insert(PathBuf::from("/test/db/rw"));
        policy.tcp_bind.insert(9090);
        policy.tcp_connect.insert(9443);

        let mut client = get_db_conn()?;
        // Delete any record for this app (for testing, ignoring roles here)
        client.execute("DELETE FROM app_policy WHERE app_name = $1", &[&app_name])?;

        // Call update_policy_in_db with a dummy user.
        let dummy_user = User { user_id: 1, username: "test".into() };
        update_policy_in_db(app_name, &policy, &dummy_user)?;

        // Now fetch the policy back from DB
        let fetched_policy = fetch_policy_from_db(app_name, &dummy_user)?;
        assert_eq!(fetched_policy.ro_paths, policy.ro_paths);
        assert_eq!(fetched_policy.rw_paths, policy.rw_paths);
        assert_eq!(fetched_policy.tcp_bind, policy.tcp_bind);
        assert_eq!(fetched_policy.tcp_connect, policy.tcp_connect);

        // Clean up afterward
        client.execute("DELETE FROM app_policy WHERE app_name = $1", &[&app_name])?;
        Ok(())
    }

    /// Verifies that parse_denied_lines picks up a denied path from our mock log.
    #[test]
    fn test_parse_denied_lines() -> Result<()> {
        use std::fs::File;
        use std::io::Write;
        use tempfile::TempDir;

        let tempdir = TempDir::new()?;
        let mock_file_path = tempdir.path().join("mock_sandbox_test.log");

        // Write a line that `parse_denied_lines` should recognize as a denial.
        {
            let mut file = File::create(&mock_file_path)?;
            writeln!(
                file,
                r#"openat(AT_FDCWD, "/some/denied/path", O_RDONLY) = -1 EACCES (Permission denied)"#
            )?;
        }

        // parse_denied_lines now returns a HashSet<String>, so we check using string membership
        let results = parse_denied_lines(tempdir.path(), "mock_sandbox_test.log")?;
        assert_eq!(results.len(), 1);
        assert!(results.contains("/some/denied/path"));

        Ok(())
    }
}