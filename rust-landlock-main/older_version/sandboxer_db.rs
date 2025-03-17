use anyhow::{anyhow, Context, Result};
use dialoguer::{Select, Confirm};
use landlock::{
    Access, AccessFs, AccessNet, ABI, NetPort, PathBeneath, PathFd, Ruleset, RulesetStatus,
    RulesetAttr, RulesetCreatedAttr,
};
use postgres::{Client, NoTls};
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use hostname::get as get_hostname_raw;

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


fn db_client() -> Result<Client> {
    let conn_str =
        "host=127.0.0.1 port=5432 user=sandboxuser password=supernanny dbname=sandboxdb";
    Client::connect(conn_str, NoTls).context("Failed to connect to PostgreSQL")
}

fn fetch_policy_from_db(app: &str) -> Result<AppPolicy> {
    let mut client = db_client()?;
    let query =
        "SELECT default_ro, default_rw, tcp_bind, tcp_connect FROM app_policy WHERE app_name = $1";
    if let Some(row) = client.query_opt(query, &[&app])? {
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
    let mut client = db_client()?;
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
    client.execute(
        sql,
        &[
            &app,
            &AppPolicy::join_paths(&policy.ro_paths),
            &AppPolicy::join_paths(&policy.rw_paths),
            &AppPolicy::join_ports(&policy.tcp_bind),
            &AppPolicy::join_ports(&policy.tcp_connect),
        ],
    )?;
    Ok(())
}

fn get_hostname() -> String {
    get_hostname_raw()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .into_owned()
}

fn log_event(app: &str, path: &Path, operation: &str, result: &str) -> Result<()> {
    let hostname = get_hostname();
    let denied_path = path.to_string_lossy().into_owned();
    let mut client = db_client()?;
    let sql = r#"
        INSERT INTO sandbox_events (event_id, hostname, app_name, denied_path, operation, result)
        VALUES (DEFAULT, $1, $2, $3, $4, $5)
    "#;
    client.execute(sql, &[&hostname, &app, &denied_path, &operation, &result])?;
    Ok(())
}

fn enforce_landlock(policy: &AppPolicy) -> Result<()> {
    let abi = ABI::V5;
    let base = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::BindTcp)?
        .handle_access(AccessNet::ConnectTcp)?;

    // Because handle_access consumes self, we store result in 'created'
    let mut created = base.create()?;

    // Add read-only paths
    for path in &policy.ro_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str())?;
            let rule = PathBeneath::new(fd, AccessFs::from_read(abi));
            created = created.add_rule(rule)?;
        }
    }

    // Add read-write paths
    for path in &policy.rw_paths {
        if let Ok(canonical_path) = fs::canonicalize(path) {
            let fd = PathFd::new(canonical_path.as_os_str())?;
            let rule = PathBeneath::new(fd, AccessFs::from_all(abi));
            created = created.add_rule(rule)?;
        }
    }

    // Add TCP rules
    for port in &policy.tcp_bind {
        created = created.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
    }
    for port in &policy.tcp_connect {
        created = created.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
    }

    let status = created.restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(anyhow!("Landlock is not supported by the running kernel"));
    }

    println!("Landlock ruleset enforced successfully.");
    Ok(())
}

fn clear_logs(prefix: &str) -> Result<()> {
    let log_dir = "/tmp";
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        if let Some(fname) = entry.file_name().to_str() {
            if fname.starts_with(prefix) {
                fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

fn run_sandbox_run_mode(
    app: &str,
    app_args: &[String],
    policy: &AppPolicy,
    log_file: &str,
    _label: &str,
) -> Result<std::process::ExitStatus> {
    clear_logs(log_file)?;

    let mut child_env = env::vars().collect::<Vec<(String, String)>>();
    child_env.push(("LL_FS_RO".into(), AppPolicy::join_paths(&policy.ro_paths)));
    child_env.push(("LL_FS_RW".into(), AppPolicy::join_paths(&policy.rw_paths)));
    child_env.push(("LL_TCP_BIND".into(), AppPolicy::join_ports(&policy.tcp_bind)));
    child_env.push(("LL_TCP_CONNECT".into(), AppPolicy::join_ports(&policy.tcp_connect)));
    child_env.push(("SANDBOX_CHILD".into(), "1".into()));

    let mut new_args = vec!["--sandbox".to_string(), app.to_string()];
    new_args.extend_from_slice(app_args);

    let current_exe = env::current_exe().context("Failed to get current executable")?;
    let log_path = format!("/tmp/{}", log_file);

    let status = Command::new("strace")
        .args(&["-ff", "-yy", "-e", "trace=file,process,openat,getdents,stat", "-o", &log_path])
        .arg(&current_exe)
        .args(&new_args)
        .env_clear()
        .envs(child_env)
        .status()?;

    Ok(status)
}

fn parse_denied_lines(log_file: &str) -> Result<HashSet<PathBuf>> {
    let re = Regex::new(
        r#"(?x)
        (?:openat\(.*?,\s*"([^"]+)" |  
           (?:open|stat|execve|access|readlink)\("([^"]+)" |
           getdents(?:64)?\(.*?,\s*"([^"]+)"
        )
        .*?EACCES|EPERM
        "#
    )?;

    let mut denials = HashSet::new();

    for entry in fs::read_dir("/tmp")? {
        let entry = entry?;
        if entry.file_name().to_str().unwrap_or("").starts_with(log_file) {
            let file = File::open(entry.path())?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if let Some(caps) = re.captures(&line) {
                    let path_str = caps.get(1)
                        .or_else(|| caps.get(2))
                        .or_else(|| caps.get(3))
                        .map(|m| m.as_str())
                        .unwrap_or("");

                    if !path_str.is_empty() {
                        let abs_path = if path_str == "." {
                            env::current_dir()?
                        } else {
                            fs::canonicalize(path_str).unwrap_or_else(|_| PathBuf::from(path_str))
                        };
                        denials.insert(abs_path);
                    }
                }
            }
        }
    }
    Ok(denials)
}

fn process_denials(log_file: &str, policy: &mut AppPolicy, app: &str) -> Result<bool> {
    let denied_paths = parse_denied_lines(log_file)?;
    let mut updated = false;

    for path in denied_paths {
        if policy.contains_path(&path) || is_symlink(&path) {
            continue;
        }
        // In a real test environment, you'd skip interactive prompts
        // or mock them. We'll leave the code here for demonstration.
        let choices = &["Read-Only", "Read-Write", "Deny"];
        let selection = Select::new()
            .with_prompt(format!("Access denied for {}. Allow as:", path.display()))
            .items(choices)
            .default(2)
            .interact()?;
        match selection {
            0 => {
                policy.ro_paths.insert(path.clone());
                log_event(app, &path, "syscall", "granted_ro")?;
                updated = true;
            }
            1 => {
                policy.rw_paths.insert(path.clone());
                log_event(app, &path, "syscall", "granted_rw")?;
                updated = true;
            }
            _ => {
                log_event(app, &path, "syscall", "denied")?;
            }
        }
    }
    Ok(updated)
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn management_flow() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(anyhow!("Usage: {} <APP> [ARGS...]", args[0]));
    }
    let app = &args[1];
    let app_args = &args[2..];
    let mut policy = fetch_policy_from_db(app)?;

    let first_log = "sandboxer_first.log";
    let first_status = run_sandbox_run_mode(app, app_args, &policy, first_log, "first")?;
    let first_success = first_status.success();
    let first_denials = parse_denied_lines(first_log)?;

    if !first_denials.is_empty() || !first_success {
        println!("Denied operations detected or the program failed. Processing...");
        let changed = process_denials(first_log, &mut policy, app)?;
        if changed {
            println!("Updating policy in the database...");
            update_policy_in_db(app, &policy)?;
        }

        // Ask user if they want to run again with updated policy
        let do_second_run = Confirm::new()
            .with_prompt("Would you like to run the application again with the updated policy?")
            .default(true)
            .interact()?;

        if do_second_run {
            let second_log = "sandboxer_second.log";
            let second_status = run_sandbox_run_mode(app, app_args, &policy, second_log, "second")?;
            let second_success = second_status.success();
            let second_denials = parse_denied_lines(second_log)?;

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
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} --sandbox <APP> [ARGS...]", args[0]);
        std::process::exit(1);
    }
    let cmd = &args[2];
    let cmd_args = &args[3..];

    let policy = AppPolicy {
        ro_paths: env::var("LL_FS_RO").unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        rw_paths: env::var("LL_FS_RW").unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        tcp_bind: env::var("LL_TCP_BIND").unwrap_or_default()
            .split(':')
            .filter_map(|s| s.parse::<u16>().ok())
            .collect(),
        tcp_connect: env::var("LL_TCP_CONNECT").unwrap_or_default()
            .split(':')
            .filter_map(|s| s.parse::<u16>().ok())
            .collect(),
    };

    if let Err(e) = enforce_landlock(&policy) {
        eprintln!("Failed to enforce Landlock rules: {}", e);
        std::process::exit(1);
    }

    match Command::new(cmd).args(cmd_args).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("Failed to execute command in sandbox mode: {}", e);
            std::process::exit(1)
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if env::var("SANDBOX_CHILD").is_ok() || (args.len() >= 2 && args[1] == "--sandbox") {
        sandbox_main();
    } else {
        management_flow()?;
    }
    Ok(())
}

// -----------------------------------------------------------------------
// Test code begins here.
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // A helper that won't spawn or enforce Landlock in tests.
    // Just checks logic for default policy, DB policy, etc.
    #[test]
    fn test_default_policy() {
        let policy = AppPolicy::default_policy();
        // We expect some known entries in ro_paths from the default definition
        assert!(policy.ro_paths.contains(Path::new("/bin")));
        assert!(policy.ro_paths.contains(Path::new("/etc")));
        assert!(policy.rw_paths.contains(Path::new("/tmp")));
    }

    // Demonstrates how to test a function that doesn't require
    // actual DB or Landlock. This is purely logic-based.
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

    #[test]
    fn test_db_interaction() -> Result<()> {
        let app_name = "test_db_interaction_app";

        // Create test policy with unique values
        let mut policy = AppPolicy::default_policy();
        policy.ro_paths.insert(PathBuf::from("/test/db/path"));
        policy.rw_paths.insert(PathBuf::from("/test/db/rw"));
        policy.tcp_bind.insert(9090);
        policy.tcp_connect.insert(9443);

        // Ensure we start with a clean slate
        let mut client = db_client()?;
        client.execute("DELETE FROM app_policy WHERE app_name = $1", &[&app_name])?;

        // Test policy insertion
        update_policy_in_db(app_name, &policy)?;

        // Test policy retrieval
        let fetched_policy = fetch_policy_from_db(app_name)?;

        // Verify all fields match
        assert_eq!(fetched_policy.ro_paths, policy.ro_paths, "RO paths mismatch");
        assert_eq!(fetched_policy.rw_paths, policy.rw_paths, "RW paths mismatch");
        assert_eq!(fetched_policy.tcp_bind, policy.tcp_bind, "TCP bind ports mismatch");
        assert_eq!(fetched_policy.tcp_connect, policy.tcp_connect, "TCP connect ports mismatch");

        // Cleanup
        client.execute("DELETE FROM app_policy WHERE app_name = $1", &[&app_name])?;

        Ok(())
    }

    // parse_denied_lines() test with mock log files
    #[test]
    fn test_parse_denied_lines() -> Result<()> {
        use std::io::Write;

        // Create a mock strace log in /tmp
        let mock_log_path = "/tmp/mock_sandbox_test.log";
        {
            let mut file = File::create(mock_log_path)?;
            // A fake line that looks like open("/some/denied/path", ...) = -1 EACCES
            // Real lines would be more elaborate, but we just need to match the regex
            writeln!(
                file,
                r#"openat(AT_FDCWD, "/some/denied/path", O_RDONLY) = -1 EACCES (Permission denied)"#
            )?;
        }

        let result = parse_denied_lines("mock_sandbox_test.log")?;
        // Clean up the test file
        let _ = fs::remove_file(mock_log_path);

        assert_eq!(result.len(), 1);
        assert!(result.contains(Path::new("/some/denied/path")));
        Ok(())
    }
}
