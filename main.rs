use anyhow::{anyhow, bail, Context};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

const ENV_FS_RO_NAME: &str = "RO";
const ENV_FS_RW_NAME: &str = "RW";
const ENV_TCP_CONNECT_NAME: &str = "TCP_CONNECT";
const ENV_NO_ACCESS_NAME: &str = "NO_ACCESS";

struct PathEnv {
    paths: Vec<u8>,
    access: BitFlags<AccessFs>,
}

impl PathEnv {
    fn new<'a>(name: &'a str, access: BitFlags<AccessFs>) -> anyhow::Result<Self> {
        Ok(Self {
            paths: env::var_os(name)
                .ok_or(anyhow!("missing environment variable {name}"))?
                .into_vec(),
            access,
        })
    }

    fn iter(&self) -> impl Iterator<Item = anyhow::Result<PathBeneath<PathFd>>> + '_ {
        let is_empty = self.paths.is_empty();
        self.paths
            .split(|b| *b == b':')
            .skip_while(move |_| is_empty)
            .map(OsStr::from_bytes)
            .map(move |path| Ok(PathBeneath::new(PathFd::new(path)?, self.access)))
    }
}

struct PortEnv {
    ports: Vec<u8>,
    access: AccessNet,
}

impl PortEnv {
    fn new<'a>(name: &'a str, access: AccessNet) -> anyhow::Result<Self> {
        Ok(Self {
            ports: env::var_os(name).unwrap_or_default().into_vec(),
            access,
        })
    }

    fn iter(&self) -> impl Iterator<Item = anyhow::Result<NetPort>> + '_ {
        let is_empty = self.ports.is_empty();
        self.ports
            .split(|b| *b == b':')
            .skip_while(move |_| is_empty)
            .map(OsStr::from_bytes)
            .map(|port| {
                let port = port
                    .to_str()
                    .ok_or_else(|| anyhow!("failed to convert port string"))?
                    .parse::<u16>()
                    .map_err(|_| anyhow!("failed to convert port to 16-bit integer"))?;
                Ok(NetPort::new(port, self.access))
            })
    }
}

struct NoAccessEnv {
    paths: Vec<u8>,
}

impl NoAccessEnv {
    fn new<'a>(name: &'a str) -> anyhow::Result<Self> {
        Ok(Self {
            paths: env::var_os(name).unwrap_or_default().into_vec(),
        })
    }

    fn iter(&self) -> impl Iterator<Item = anyhow::Result<PathBeneath<PathFd>>> + '_ {
        let is_empty = self.paths.is_empty();
        self.paths
            .split(|b| *b == b':')
            .skip_while(move |_| is_empty)
            .map(OsStr::from_bytes)
            .map(|path| Ok(PathBeneath::new(PathFd::new(path)?, AccessFs::from_all(ABI::V1))))
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args_os();
    let program_name = args
        .next()
        .ok_or_else(|| anyhow!("Missing the sandboxer program name (i.e. argv[0])"))?;

    let cmd_name = args.next().ok_or_else(|| {
        let program_name = program_name.to_string_lossy();
        eprintln!(
            "usage: {ENV_FS_RO_NAME}=\"...\" {ENV_FS_RW_NAME}=\"...\" {ENV_NO_ACCESS_NAME}=\"...\" {program_name} <cmd> [args]...\n"
        );
        eprintln!("Launch a command in a restricted environment.\n");
        eprintln!("Environment variables containing paths and ports, each separated by a colon:");
        eprintln!("* {ENV_FS_RO_NAME}: list of paths allowed to be used in a read-only way.");
        eprintln!("* {ENV_FS_RW_NAME}: list of paths allowed to be used in a read-write way.");
        eprintln!("* {ENV_NO_ACCESS_NAME}: list of paths with no access rights.");
        eprintln!("Environment variables containing ports are optional and could be skipped.");
        eprintln!("* {ENV_TCP_CONNECT_NAME}: list of ports allowed to connect (client).");
        eprintln!(
            "\nexample:\n\
                {ENV_FS_RO_NAME}=\"/bin:/lib:/usr:/proc:/etc:/dev/urandom\" \
                {ENV_FS_RW_NAME}=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" \
                {ENV_NO_ACCESS_NAME}=\"/root:/etc/ssh:/var/log\" \
                {ENV_TCP_CONNECT_NAME}=\"80:443\" \
                {program_name} bash -i\n"
        );
        anyhow!("Missing command")
    })?;

    let abi = ABI::V1;
    let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
    let ruleset_ref = &mut ruleset;

    if env::var_os(ENV_TCP_CONNECT_NAME).is_some() {
        ruleset_ref.handle_access(AccessNet::ConnectTcp)?;
    }
    let status = ruleset
        .create()?
        .add_rules(PathEnv::new(ENV_FS_RO_NAME, AccessFs::from_read(abi))?.iter())?
        .add_rules(PathEnv::new(ENV_FS_RW_NAME, AccessFs::from_all(abi))?.iter())?
        .add_rules(NoAccessEnv::new(ENV_NO_ACCESS_NAME)?.iter())? // Ajoute la règle pour interdire l'accès
        .restrict_self()
        .expect("Failed to enforce ruleset");

    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported by the running kernel.");
    }

    Err(Command::new(cmd_name)
        .env_remove(ENV_FS_RO_NAME)
        .env_remove(ENV_FS_RW_NAME)
        .env_remove(ENV_TCP_CONNECT_NAME)
        .env_remove(ENV_NO_ACCESS_NAME) // Supprimer la variable d'environnement NO_ACCESS
        .args(args)
        .exec()
        .into())
}
