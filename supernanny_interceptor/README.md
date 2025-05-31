# SuperNanny eBPF Interceptor


**SuperNanny** is an eBPF (Extended Berkeley Packet Filter) based process interceptor written in Rust, designed to:
- **Monitor** every command execution (`execve`, `execveat`) on the system.
- **Filter** specific executables (bash, docker run -it, etc.).
- **Respawn** legitimate processes through a confinement binary named `supernanny`.
- **Prevent** the execution of unauthorized shells, malicious containers, or sensitive commands outside the expected context.

The project relies on:
- **Rust** for the userland part (`ebpf-service`) and confinement logic.
- **Aya** (Rust crate) to load and attach the eBPF program to the `sys_enter_execve` / `sys_enter_execveat` tracepoint.
- An auxiliary binary named `supernanny` (not detailed here) which enforces a security policy before executing the "intercepted" binary.

---

## Table of Contents

1. [Features](#features)
2. [General Architecture](#general-architecture)
3. [Requirements](#requirements)
4. [Installation & Compilation](#installation--compilation)
5. [Usage](#usage)
   - [Starting the Interceptor](#starting-the-interceptor)
   - [Typical Scenarios](#typical-scenarios)
6. [Project Structure & Main Code](#project-structure--main-code)
   1. [File Organization](#file-organization)
   2. [eBPF Program (kern)](#ebpf-program-kern)
   3. [Rust Service (mod `integration`)](#rust-service-mod-integration)
       - [Function `handle_exec_event`](#function-handle_exec_event)

---

## <a name="features"></a>1. Features

- **Real-time monitoring** of every `execve(2)` and `execveat(2)` call via an eBPF TracePoint probe.
- **Fine-grained filtering**:
  - Applies only to interactive shells (real TTYs: `/dev/pts/*` or `/dev/tty*`).
  - Ignores processes launched inside containers (cgroup/namespace detection).
  - Does not intercept UIDs < 1000 (system accounts) or the `supernanny` binary itself.
  - Explicitly ignores interpreters like `dash`, `sh`, or `xterm` to avoid over-filtering.
- **Secure respawning**:
  - For a graphical `bash` (launched from Gnome Terminal, Konsole, etc.), the original `bash` is killed and relaunched in the same TTY, with the same UID/GID, in the same working directory, adding the `-l` flag to load the user's profile.
  - For any other intercepted binary (other than `bash`/docker/sh/dash/xterm), the original process is killed and relaunched via `supernanny /canonical/path/exe args…` in the same TTY, same cwd, with essential environment variables (`DISPLAY`, `XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS`...).
- **`supernanny` Policy**:
  - Applies an access policy (via AppArmor, SELinux, or equivalent) before launching the canonical executable.
  - Blocks or logs unauthorized accesses (e.g., access to `/home/user/SupperNanny`, attempts to write to `/root`, etc.).
  - Configurable "Debug" mode to view authentication, applied policies, denied accesses, etc.

---

## <a name="general-architecture"></a>2. General Architecture

```text
├── README.md
├── Cargo.toml
├── build.rs
├── src
│   ├── ebpf
│   │   └── kern
│   │       ├── exec_intercept.c      # eBPF Program (C)
│   │       └── ...                   # Other headers / eBPF Makefile
│   ├── ebpf_interceptor.rs           # Rust Service Entry Point
│   └── integration
│       └── mod.rs                    # Main interception logic
└── target/                           # Compiled binary
```
1.  `build.rs`
Automatically compiles the eBPF code (`exec_intercept.c`) into CO-RE bytecode and embeds it into the Rust binary via Aya.

<br>

2. `src/ebpf/kern/exec_intercept.c`

    C file compiled into eBPF. It contains a simple tracepoint that fills a `PERF_EVENT_ARRAY` map with an `ExecEvent` structure at each `execve(2)` or `execveat(2)` call.

<br>

3.  `src/ebpf_interceptor.rs`

    The entry point of the Rust application. It:

    - Loads the eBPF bytecode.
    - Attaches two TracePoints: `sys_enter_execve` and `sys_enter_execveat`.
    - Loops to read events via `PerfEventArray`.
    - Calls `handle_exec_event(ev)` for each event.

<br>

4. `src/integration/mod.rs`

    Contains all utility functions (reading `/proc/...`, container detection, argument reconstruction, etc.) and the key function `handle_exec_event` (see below).

<br>

5. `supernanny` (auxiliary binary)
Although not detailed here, it is the binary that:

    - Receives the canonical command + intercepted arguments.
    - Checks the security policy (via AppArmor / SELinux / eBPF LSM / etc.).
    - Launches the real binary or denies it based on the policy.

---

## <a name="prérequis"></a>3. Requirements

1. Recent Linux system (kernel ≥ 5.x) with eBPF support.
2. Rust (version 1.65.0 or later) + Cargo.
3. Clang/LLVM (to compile the C eBPF code).

    ```bash
    sudo apt-get install clang llvm libelf-dev gcc make
4. pkg-config, libbpf-dev (optional, depending on your distribution).
    ```bash
    sudo apt-get install pkg-config libbpf-dev
5. Permissions:

    - To load eBPF programs, the kernel must be configured with CONFIG_BPF_SYSCALL=y and CONFIG_DEBUG_INFO_BTF=y.

    - Run the interceptor with sudo (or with CAP_SYS_ADMIN, CAP_BPF capabilities).

    - Ensure that /sys/kernel/debug/tracing is mounted:
    ```bash
    mount -t tracefs nodev /sys/kernel/debug/tracing

---

## <a name="installation--compilation"></a>4. Installation & Compilation

1. Clone the repository
    ```bash
    git clone https://github.com/your-user/SuperNanny-ebpf-interceptor.git
    cd SuperNanny-ebpf-interceptor
2. Install eBPF dependencies
    ```bash
    sudo apt-get update
    sudo apt-get install clang llvm libelf-dev gcc make pkg-config libbpf-dev
3. Compile the project
    ```bash
    # build.rs will compile exec_intercept.c into eBPF bytecode
    cargo build --release
4. The main binary will be generated in
    ```bash
    target/release/ebpf_interceptor
5. The compiled eBPF program (.o) will be under
    ```bash
    target/bpf/exec_intercept.o
6. Optionnal
    ```bash
    sudo cp target/release/ebpf_interceptor 
    /usr/bin/ebpf_interceptor
    ```
    Ensure the supernanny binary (policy enforcer) is in your PATH and executable (e.g., /usr/bin/supernanny).

---

## <a name="utilisation"></a>5. Usage

<a name="démarrage-de-lintercepteur"></a>5.1. Starting the Interceptor

Run the interceptor with root privileges (eBPF capabilities):
```bash
sudo ./target/release/ebpf_interceptor
```
You should see:
```bash
2025-05-30T00:00:00.000000Z INFO ebpf_interceptor: 🛡️  Starting SuperNanny eBPF interceptor…
2025-05-30T00:00:00.000001Z INFO ebpf_service::integration: 🔧 Loading eBPF program...
```

### <a name="scénarios-typiques"></a>5.2. Typical Scenarios

1. From another terminal:
```bash
user@host:~$ ls -l
🔍 Intercepted: /usr/bin/ls → ["-l"]
✅ supernanny exited: exit status: 0
```
The ls -l call is properly intercepted and relayed through supernanny.

If the policy is restrictive, ls might be blocked.

2. Launch a root shell (or sudo):
```bash
user@host:~$ sudo bash
🔍 Intercepted: /usr/bin/bash → ["-p","-c","echo \"root shell\""]
❌ supernanny failed: Permission denied
```
→ By default, supernanny policy may deny privilege escalation if the current user is not authorized.

3. Launch Docker in interactive mode:
```bash
user@host:~$ docker run -it ubuntu /bin/bash
🔍 Intercepted interactive Docker run: docker ["run","-i","-t","ubuntu","/bin/bash"]
```
→ You can add logic to launch an xterm or other container within the same TTY via supernanny.


---


## <a name="structure-du-projet--code-principal"></a>6. Project Structure & Main Code

### <a name="organisation-des-fichiers"></a>6.1. File Organization

```bash
SuperNanny-ebpf-interceptor/
│
├── build.rs
├── Cargo.toml
├── README.md
└── src
├── ebpf
│ └── kern
│ ├── exec_intercept.c # eBPF Program
│ └── Makefile # (optional) for compiling
├── ebpf_interceptor.rs # Rust Entry Point
└── integration
└── mod.rs # Interception Logic
```


### <a name="service-rust-mod-integration"></a>6.2. Rust Service (mod integration)

The key file is src/integration/mod.rs, containing:

    Utility functions:

        is_in_container(pid: u32) -> bool
        Checks if the PID belongs to a container (cgroup or PID namespace).

        read_proc_environ(pid: u32) -> HashMap<String, String>
        Reads /proc/<pid>/environ into a HashMap (key=value).

        absolutize_args(pid: u32, args: Vec<String>) -> Vec<String>
        Converts relative argument paths to absolute paths based on the PID's cwd.

        reconstruct_args(ev: &ExecEvent) -> (String, Vec<String>)
        Extracts the basename (binary short name) and builds a Vec<String> for arguments (splits -it into -i, -t).

        is_interactive_docker_cmd(basename: &str, args: &[String]) -> bool
        Returns true if the call matches docker run -i -t ....

    The critical function:
    handle_exec_event(ev: ExecEvent)
    This function is called for each eBPF ExecEvent. The full version is detailed below.

### <a name="fonction-handle_exec_event"></a>6.2.1. Function handle_exec_event

(Full Rust code not inlined here for brevity, but the comments are detailed below.)

Detailed comments:

    Initial data:
    Retrieve the PID, UID, the process environment table (read_proc_environ(pid)), and the original working directory (/proc/<pid>/cwd).

    Verify TTY:
    Read /proc/<pid>/fd/0 to check if the process has a real TTY (/dev/pts/* or /dev/tty*). If not, abort, as only interactive shells are intercepted.

    GID retrieval:
    Extract the original GID to relaunch a bash in the same group context.

    Environment variable NO_INTERCEPT=1:
    Skip if set and the parent is already supernanny or xterm.

    Skip containers:
    Do not intercept if the process is running inside a container (is_in_container(pid)).

    Skip system processes:
    Ignore if the parent is supernanny or if UID < 1000 (system accounts).

    Basename and arguments reconstruction:
    Build the basename (short binary name) and the argument vector (splitting -it/-ti for Docker).

    Explicit skip for interpreters:
    Explicitly skip dash and sh to prevent intercepting them.

    Special case — Bash launched by graphical terminal:

        If basename == "bash" and no arguments (args.is_empty()), check the parent (parent_exe).

        If the parent ends with gnome-terminal, konsole, or x-terminal-emulator, it's a graphical shell.

        Kill the original bash (kill(pid, SIGKILL)) and relaunch a bash -l in the same TTY, same UID/GID, setting the session (setsid()) and attaching the TTY (ioctl(TIOCSCTTY)).

        The new bash runs in the same working directory (original_cwd) and inherits environment variables (HOME, USER, etc.) to simulate a "normal" shell.

    Special case — Docker docker run -it ...:

        If the combination matches a docker run -i -t, kill the original PID and replace it with an xterm -e supernanny ... or equivalent (not detailed here).

        Note: This section can be extended to redirect to a graphical terminal or another wrapper.

    Catch-all (default case):

        Read /proc/<pid>/exe to get the full canonical executable path (avoiding symlink tricks).

        Kill the original process (kill(pid, SIGKILL)).

        Launch supernanny /canonical/path/exe arg1 arg2 ... in the same working directory (current_dir(original_cwd)) and in the same TTY (pre_exec + ioctl(TIOCSCTTY)).

        supernanny will then enforce the policy (via AppArmor/SELinux/eBPF LSM, etc.) before re-executing or blocking the binary.

