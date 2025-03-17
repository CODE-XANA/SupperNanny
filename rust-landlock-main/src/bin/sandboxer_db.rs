use anyhow::{anyhow, Context, Result};
use dialoguer::{Select, Confirm};
use landlock::{
    Access, AccessFs, AccessNet, ABI, NetPort, PathBeneath, PathFd, Ruleset, RulesetStatus,
    RulesetAttr, RulesetCreatedAttr,
};
use postgres::{Config, NoTls};
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use hostname::get as get_hostname_raw;
use dotenv::dotenv;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;
use once_cell::sync::Lazy;
use tempfile::TempDir;

// -----------------------------------------------------------------------
// Production code begins here.
// -----------------------------------------------------------------------

#[derive(Debug)]
struct AppPolicy {
    ro_paths: HashSet<PathBuf>,
    rw_paths: HashSet<PathBuf>,
    tcp_bind: HashSet<u16>,
    tcp_connect: HashSet<u16>,
}

impl AppPolicy {
    fn default_policy() -> Self {
        Self {
            ro_paths: "/bin:/usr:/dev/urandom:/etc:/proc:/lib"
                .split(':')
                .map(PathBuf::from)
                .collect(),
            rw_paths: "/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null"
                .split(':')
                .map(PathBuf::from)
                .collect(),
            tcp_bind: "9418"
                .split(':')
                .filter_map(|s| s.parse::<u16>().ok())
                .collect(),
            tcp_connect: "80:443"
                .split(':')
                .filter_map(|s| s.parse::<u16>().ok())
                .collect(),
        }
    }

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
}

// Our global static pool
static POOL: Lazy<Pool<PostgresConnectionManager<NoTls>>> = Lazy::new(|| {
    dotenv().ok();

    let host = env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("DB_PORT").unwrap_or_else(|_| "5432".to_string());
    let user = env::var("DB_USER").unwrap_or_else(|_| "sandboxuser".to_string());
    let pass = env::var("DB_PASS").unwrap_or_else(|_| "supersecret".to_string());
    let dbname = env::var("DB_NAME").unwrap_or_else(|_| "sandboxdb".to_string());

    let mut pg_config = Config::new();
    pg_config
        .host(&host)
        .port(port.parse().unwrap_or(5432))
        .user(&user)
        .password(&pass)
        .dbname(&dbname);

    let manager = PostgresConnectionManager::new(pg_config, NoTls);

    Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create pool.")
});

// A small helper function to get a connection from the pool
pub fn get_db_conn() -> Result<r2d2::PooledConnection<PostgresConnectionManager<NoTls>>> {
    POOL.get().context("Failed to get DB connection from pool")
}

// -----------------------------------------------------------------------
// DB Functions
// -----------------------------------------------------------------------

fn fetch_policy_from_db(app: &str) -> Result<AppPolicy> {
    let mut client = get_db_conn().context("Could not fetch DB connection to retrieve policy")?; // [EH-IMPROVED]
    let query =
        "SELECT default_ro, default_rw, tcp_bind, tcp_connect FROM app_policy WHERE app_name = $1";

    let row_opt = client
        .query_opt(query, &[&app])
        .with_context(|| format!("Failed to query policy for app '{}'", app))?; // [EH-IMPROVED]

    if let Some(row) = row_opt {
        let ro: String = row.get(0);
        let rw: String = row.get(1);
        let bind: String = row.get(2);
        let connect: String = row.get(3);

        let ro_paths = ro.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect();
        let rw_paths = rw.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect();
        let tcp_bind = bind.split(':').filter_map(|s| s.parse::<u16>().ok()).collect();
        let tcp_connect = connect.split(':').filter_map(|s| s.parse::<u16>().ok()).collect();

        Ok(AppPolicy {
            ro_paths,
            rw_paths,
            tcp_bind,
            tcp_connect,
        })
    } else {
        // fallback
        Ok(AppPolicy::default_policy())
    }
}

fn update_policy_in_db(app: &str, policy: &AppPolicy) -> Result<()> {
    let mut conn = get_db_conn().context("Could not fetch DB connection to update policy")?;
    let mut tx = conn
        .transaction()
        .context("Failed to begin transaction for updating policy")?; // [EH-IMPROVED]

    let sql = r#"
        INSERT INTO app_policy (app_name, default_ro, default_rw, tcp_bind, tcp_connect, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (app_name) DO UPDATE SET
            default_ro = EXCLUDED.default_ro,
            default_rw = EXCLUDED.default_rw,
            tcp_bind = EXCLUDED.tcp_bind,
            tcp_connect = EXCLUDED.tcp_connect,
            updated_at = NOW()
    "#;

    tx.execute(
        sql,
        &[
            &app,
            &AppPolicy::join_paths(&policy.ro_paths),
            &AppPolicy::join_paths(&policy.rw_paths),
            &AppPolicy::join_ports(&policy.tcp_bind),
            &AppPolicy::join_ports(&policy.tcp_connect),
        ],
    )
    .with_context(|| format!("Failed to UPSERT policy for app '{}'", app))?; // [EH-IMPROVED]

    tx.commit().context("Failed to commit policy update transaction")?;

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

fn log_event(app: &str, path: &Path, operation: &str, result: &str) -> Result<()> {
    let hostname = get_hostname();
    let denied_path = path.to_string_lossy().into_owned();

    let mut conn = get_db_conn().context("Could not fetch DB connection to log event")?;
    let mut tx = conn
        .transaction()
        .context("Failed to begin transaction for logging event")?;

    let sql = r#"
        INSERT INTO sandbox_events (event_id, hostname, app_name, denied_path, operation, result)
        VALUES (DEFAULT, $1, $2, $3, $4, $5)
    "#;

    tx.execute(sql, &[&hostname, &app, &denied_path, &operation, &result])
        .with_context(|| {
            format!(
                "Could not insert log event for app '{}', path '{}', operation '{}'",
                app, denied_path, operation
            )
        })?;

    tx.commit().context("Failed to commit log event transaction")?;
    Ok(())
}

// -----------------------------------------------------------------------
// Validation and Landlock
// -----------------------------------------------------------------------

/// Validate that `path_str` is an existing executable file.
/// Returns a canonicalized PathBuf on success.
pub fn validate_executable_path(path_str: &str) -> Result<std::path::PathBuf> {
    let path = PathBuf::from(path_str);

    if !path.exists() {
        // Provide context about which path is missing
        return Err(anyhow!("Executable path does not exist: {}", path_str));
    }

    let meta = fs::metadata(&path)
        .with_context(|| format!("Failed to read metadata for path '{}'", path_str))?;

    if !meta.is_file() {
        return Err(anyhow!("Path is not a regular file: {}", path_str));
    }

    #[cfg(unix)]
    {
        let perms = meta.permissions();
        let mode = perms.mode();
        if (mode & 0o111) == 0 {
            return Err(anyhow!("File is not executable: {}", path_str));
        }
    }

    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("Failed to canonicalize path '{}'", path_str))?;

    Ok(canonical)
}

fn enforce_landlock(policy: &AppPolicy) -> Result<()> {
    let abi = ABI::V5;
    let base = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::BindTcp)?
        .handle_access(AccessNet::ConnectTcp)?;

    let mut created = base.create()
        .context("Failed to create Landlock ruleset (check if Landlock is supported)")?;

    // Add read-only paths
    for path in &policy.ro_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str())
                .with_context(|| format!("Could not create PathFd for '{}'", canonical_path.display()))?;
            let rule = PathBeneath::new(fd, AccessFs::from_read(abi));
            created = created.add_rule(rule)
                .with_context(|| format!("Could not add read-only rule for '{}'", canonical_path.display()))?;
        }
    }

    // Add read-write paths
    for path in &policy.rw_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str())
                .with_context(|| format!("Could not create PathFd for '{}'", canonical_path.display()))?;
            let rule = PathBeneath::new(fd, AccessFs::from_all(abi));
            created = created.add_rule(rule)
                .with_context(|| format!("Could not add read/write rule for '{}'", canonical_path.display()))?;
        }
    }

    // Add TCP rules
    for port in &policy.tcp_bind {
        created = created.add_rule(NetPort::new(*port, AccessNet::BindTcp))
            .with_context(|| format!("Could not add TCP bind rule for port {}", port))?;
    }
    for port in &policy.tcp_connect {
        created = created.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
            .with_context(|| format!("Could not add TCP connect rule for port {}", port))?;
    }

    let status = created.restrict_self()
        .context("Failed to restrict self with Landlock ruleset")?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(anyhow!("Landlock is not supported by the running kernel"));
    }

    println!("Landlock ruleset enforced successfully.");
    Ok(())
}

// -----------------------------------------------------------------------
// run_sandbox_run_mode + parse_denied_lines + process_denials
// -----------------------------------------------------------------------

fn run_sandbox_run_mode(
    app_path: &Path,
    app_args: &[String],
    policy: &AppPolicy,
    log_file_prefix: &str,
) -> Result<(ExitStatus, TempDir)> {
    let tempdir = TempDir::new()
        .context("Failed to create temporary directory for strace logs")?;
    let log_prefix_path = tempdir.path().join(log_file_prefix);
    let log_prefix_str = log_prefix_path.to_string_lossy().to_string();

    // Prepare environment variables for the child
    let mut child_env = env::vars().collect::<Vec<(String, String)>>();
    child_env.push(("LL_FS_RO".into(), AppPolicy::join_paths(&policy.ro_paths)));
    child_env.push(("LL_FS_RW".into(), AppPolicy::join_paths(&policy.rw_paths)));
    child_env.push(("LL_TCP_BIND".into(), AppPolicy::join_ports(&policy.tcp_bind)));
    child_env.push(("LL_TCP_CONNECT".into(), AppPolicy::join_ports(&policy.tcp_connect)));

    let current_exe = env::current_exe()
        .context("Failed to get current executable for strace invocation")?;

    let status = Command::new("strace")
        .args(&["-ff", "-yy", "-e", "trace=file,process,openat,getdents,stat"])
        .arg("-o")
        .arg(&log_prefix_str)
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

fn parse_denied_lines(log_dir: &Path, prefix: &str) -> Result<HashSet<PathBuf>> {
    let path_re = Regex::new(
        r#"(?x)
        ^
        # One of these syscalls at the start of the line:
        (?:
           openat\(.*?,\s*"([^"]+)" |
           (?:open|stat|execve|access|readlink)\("([^"]+)" |
           getdents(?:64)?\(.*?,\s*"([^"]+)"
        )
        "#,
    ).context("Failed to compile syscall path regex")?;

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

        let file = fs::File::open(entry.path())
            .with_context(|| format!("Failed to open strace log file '{}'", entry.path().display()))?;
        for line_result in BufReader::new(file).lines() {
            let line = line_result
                .with_context(|| format!("Failed to read line in '{}'", entry.path().display()))?;

            if !(line.contains("EACCES") || line.contains("EPERM")) {
                continue;
            }

            if let Some(caps) = path_re.captures(&line) {
                let path_str = caps.get(1)
                    .or_else(|| caps.get(2))
                    .or_else(|| caps.get(3))
                    .map(|m| m.as_str())
                    .unwrap_or("");

                if path_str.is_empty() {
                    continue;
                }

                let resolved = if path_str == "." {
                    env::current_dir().context("Failed to get current directory for '.'")?
                } else {
                    match fs::canonicalize(path_str) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("Warning: cannot canonicalize '{}': {}", path_str, e);
                            PathBuf::from(path_str)
                        }
                    }
                };
                denials.insert(resolved);
            }
        }
    }

    Ok(denials)
}

fn process_denials(
    log_dir: &Path,
    prefix: &str,
    policy: &mut AppPolicy,
    app: &str
) -> Result<bool> {
    let denied_paths = parse_denied_lines(log_dir, prefix)
        .with_context(|| format!("Failed to parse denied lines for prefix '{}'", prefix))?;

    let mut updated = false;

    for raw_path in denied_paths {
        if policy.contains_path(&raw_path) {
            continue;
        }

        let final_path = match fs::canonicalize(&raw_path) {
            Ok(resolved) => resolved,
            Err(_) => raw_path.clone(), // fallback to raw if it fails
        };

        let choices = &["Read-Only", "Read-Write", "Deny"];
        let selection = Select::new()
            .with_prompt(format!("Access denied for {}. Allow as:", final_path.display()))
            .items(choices)
            .default(2)
            .interact()
            .context("User prompt failed")?;

        match selection {
            0 => {
                policy.ro_paths.insert(final_path.clone());
                log_event(app, &final_path, "syscall", "granted_ro")
                    .context("Failed to log 'granted_ro' event")?;
                updated = true;
            }
            1 => {
                policy.rw_paths.insert(final_path.clone());
                log_event(app, &final_path, "syscall", "granted_rw")
                    .context("Failed to log 'granted_rw' event")?;
                updated = true;
            }
            _ => {
                log_event(app, &final_path, "syscall", "denied")
                    .context("Failed to log 'denied' event")?;
            }
        }
    }

    Ok(updated)
}

// -----------------------------------------------------------------------
// management_flow and sandbox_main
// -----------------------------------------------------------------------

fn management_flow() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(anyhow!("Usage: {} <APP> [ARGS...]", args[0]));
    }
    let raw_app = &args[1];
    let app_args = &args[2..];

    // 1) Fetch existing policy from DB
    let mut policy = fetch_policy_from_db(raw_app)
        .with_context(|| format!("Failed to fetch initial policy for '{}'", raw_app))?;

    // 2) First run
    let first_prefix = "sandboxer_first.log";
    let (first_status, first_tempdir) = run_sandbox_run_mode(Path::new(raw_app), app_args, &policy, first_prefix)
        .with_context(|| format!("Failed during first run_sandbox_run_mode for '{}'", raw_app))?;
    let first_success = first_status.success();

    // 3) Parse denials
    let first_denials = parse_denied_lines(first_tempdir.path(), first_prefix)
        .context("Failed to parse denied lines from the first run")?;

    // 4) Possibly update policy
    if !first_denials.is_empty() || !first_success {
        println!("Denied operations detected or the program failed. Processing...");
        let changed = process_denials(first_tempdir.path(), first_prefix, &mut policy, raw_app)
            .context("Failed to process denials after first run")?;
        if changed {
            println!("Updating policy in the database...");
            update_policy_in_db(raw_app, &policy)
                .with_context(|| format!("Failed to update policy for '{}'", raw_app))?;
        }

        // Second run
        let do_second_run = Confirm::new()
            .with_prompt("Would you like to run the application again with the updated policy?")
            .default(true)
            .interact()
            .context("Failed to prompt for second run")?;

        if do_second_run {
            let second_prefix = "sandboxer_second.log";
            let (second_status, second_tempdir) = run_sandbox_run_mode(Path::new(raw_app), app_args, &policy, second_prefix)
                .with_context(|| format!("Failed during second run_sandbox_run_mode for '{}'", raw_app))?;
            let second_success = second_status.success();
            let second_denials = parse_denied_lines(second_tempdir.path(), second_prefix)
                .context("Failed to parse denied lines from the second run")?;

            if second_denials.is_empty() && second_success {
                println!("Second run successful. No denied operations.");
            } else {
                println!("Denied operations still detected. Further updates may be needed.");
            }
        } else {
            println!("Exiting without a second run.");
        }
    } else {
        println!("Program executed successfully under sandbox.");
    }

    Ok(())
}

fn sandbox_main() -> ! {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} --sandbox <APP> [ARGS...]", args[0]);
        std::process::exit(1);
    }

    let cmd = &args[2];
    let cmd_args = &args[3..];

    let policy = AppPolicy {
        ro_paths: std::env::var("LL_FS_RO").unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(Into::into)
            .collect(),
        rw_paths: std::env::var("LL_FS_RW").unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(Into::into)
            .collect(),
        tcp_bind: std::env::var("LL_TCP_BIND").unwrap_or_default()
            .split(':')
            .filter_map(|s| s.parse().ok())
            .collect(),
        tcp_connect: std::env::var("LL_TCP_CONNECT").unwrap_or_default()
            .split(':')
            .filter_map(|s| s.parse().ok())
            .collect(),
    };

    if let Err(e) = enforce_landlock(&policy) {
        eprintln!("Failed to enforce Landlock rules: {}", e);
        std::process::exit(1);
    }

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
            eprintln!("Error in management flow: {:?}", e);  // [EH-IMPROVED] Provide debug info
            std::process::exit(1);
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

    // Basic logic tests for AppPolicy
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
        policy.ro_paths.insert(PathBuf::from("/home"));
        let ro_joined = AppPolicy::join_paths(&policy.ro_paths);
        assert!(ro_joined.contains("/home"));

        policy.tcp_bind.insert(1234);
        let bind_joined = AppPolicy::join_ports(&policy.tcp_bind);
        assert!(bind_joined.contains("1234"));
    }

    // DB interaction tests
    #[test]
    fn test_db_interaction() -> Result<()> {
        let app_name = "test_db_interaction_app";

        let mut policy = AppPolicy::default_policy();
        policy.ro_paths.insert(PathBuf::from("/test/db/path"));
        policy.rw_paths.insert(PathBuf::from("/test/db/rw"));
        policy.tcp_bind.insert(9090);
        policy.tcp_connect.insert(9443);

        let mut client = get_db_conn()?;
        client.execute("DELETE FROM app_policy WHERE app_name = $1", &[&app_name])?;

        update_policy_in_db(app_name, &policy)?;

        let fetched_policy = fetch_policy_from_db(app_name)?;
        assert_eq!(fetched_policy.ro_paths, policy.ro_paths);
        assert_eq!(fetched_policy.rw_paths, policy.rw_paths);
        assert_eq!(fetched_policy.tcp_bind, policy.tcp_bind);
        assert_eq!(fetched_policy.tcp_connect, policy.tcp_connect);

        client.execute("DELETE FROM app_policy WHERE app_name = $1", &[&app_name])?;
        Ok(())
    }

    // parse_denied_lines() test with mock log files
    #[test]
    fn test_parse_denied_lines() -> Result<()> {
        use std::fs::File;
        use std::io::Write;
        use tempfile::TempDir;

        let tempdir = TempDir::new()?;
        let mock_file_path = tempdir.path().join("mock_sandbox_test.log");

        {
            let mut file = File::create(&mock_file_path)?;
            writeln!(
                file,
                r#"openat(AT_FDCWD, "/some/denied/path", O_RDONLY) = -1 EACCES (Permission denied)"#
            )?;
        }

        let result = parse_denied_lines(tempdir.path(), "mock_sandbox_test.log")?;
        assert_eq!(result.len(), 1);
        assert!(result.contains(Path::new("/some/denied/path")));
        Ok(())
    }
}
