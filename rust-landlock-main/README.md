# SuperNanny Sandbox

**SuperNanny** is a sandbox tool built with [Rust](https://www.rust-lang.org/) and [Landlock](https://docs.kernel.org/userspace-api/landlock.html), leveraging a PostgreSQL database to manage and store application security policies. The code for the sandbox’s main logic is contained in the [`sandboxer_db`](../src/bin/sandboxer_db.rs) file.

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Build & Installation](#build--installation)
4. [Database Setup](#database-setup)
5. [Usage](#usage)
6. [License](#license)

## Overview

- **sandboxer_db**: The main binary that:
  1. Authenticates users against a Postgres DB.
  2. Fetches/updates policies for a given application path.
  3. Runs the application under Landlock confinement.
  4. Uses `strace` to detect denied system calls and optionally updates policies dynamically.

Once installed as **`supernanny`**, you can asimply run `supernanny /path/to/app` to sandbox any application with the relevant policies.

## Requirements

- **Rust & Cargo**  
  Make sure you have a recent version of Rust installed (via [rustup](https://rustup.rs/)).

- **PostgreSQL**  
  A running PostgreSQL instance is needed. Connection details (host, port, etc.) are typically read from a `.env` file.

- **Landlock Support**  
  Requires Linux **5.13** or newer for full Landlock functionality.

- **strace** (optional but recommended)  
  Used to detect denied syscalls in “learning” mode. Install with your system’s package manager.

## Build & Installation

1. **Clone** the repository and go into its directory (example):

   ```bash
   git clone https://github.com/yourusername/rust-landlock.git
   cd rust-landlock
   ```

2. **Build** the `sandboxer_db` binary (release mode is recommended):

   ```bash
   cargo build --release --bin sandboxer_db
   ```

   This produces the binary at `target/release/sandboxer_db`.

3. **Install** it as the `supernanny` command:

   ```bash
   sudo cp target/release/sandboxer_db /usr/local/bin/supernanny
   sudo chmod +x /usr/local/bin/supernanny
   ```

   Now `supernanny` is accessible system-wide.

> **Tip**: If you rebuild frequently, use a **symbolic link** so you don’t have to copy each time:

```bash
sudo ln -sf "$(realpath target/release/sandboxer_db)" /usr/local/bin/supernanny
```

## Database Setup

1. **Create/Edit a `.env` File**  
   In your project directory, add a `.env` file with your DB connection info:

   ```ini
   DB_HOST=127.0.0.1
   DB_PORT=5432
   DB_USER=sandboxuser
   DB_PASS=supernanny
   DB_NAME=sandboxdb
   STRACE_PATH=/usr/bin/strace
   ```

2. **Run the SQL Setup Script** (if provided):  
   If you have `sandboxdb_full_setup.sql`, run:

   ```bash
   psql -U postgres -d sandboxdb -f sandboxdb_full_setup.sql
   ```

   This creates all required tables (`users`, `roles`, `app_policy`, etc.) and seeds sample data (user accounts, default policies, etc.).

## Usage

With everything built and installed, the usual workflow is:

```bash
supernanny /usr/bin/my-app arg1 arg2 ...
```

1. **User Login**  
   You’ll be prompted for a username and password (stored in the `users` table of the DB).

2. **Policy Fetch**  
   The tool retrieves the relevant policy for your specified application path (e.g., `/usr/bin/my-app`) based on your role(s).

3. **Landlock Enforcement**  
   The application runs under a Landlock sandbox. Denied operations (file/network) are logged.

4. **Interactive Updates** (if you have `manage_policies` permission)  
   If new denials are encountered, you can decide how to handle them (add read-only/read-write paths or bind/connect for network ports). Updated policies are saved in the DB for future runs.

5. **Second Run (Optional)**  
   You can optionally run the application again to confirm no further denials occur.

## License

[MIT](https://choosealicense.com/licenses/mit/)

![ISEN Logo](./images/logo_isen.png)
![SuperNanny Logo](./images/logo_supernanny.png)
![Landlock Logo](./images/landlock.svg)
