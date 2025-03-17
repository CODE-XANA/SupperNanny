# Supernanny Sandboxer

<div style="display: flex; justify-content: center; align-items: center; gap: 20px;">
  <div>
    <img src="images/logo_supernanny.png" alt="Supernanny Logo" style="max-width: 100%; height: auto;"/>
  </div>
  <div>
    <img src="images/logo_isen.png" alt="ISEN Logo" style="max-width: 100%; height: auto;"/>
  </div>
</div>

## Overview

Supernanny is a project that includes a sandboxing component called "Sandboxer." This module is designed to enforce security policies on applications, ensuring they operate within defined constraints. The Sandboxer uses Landlock to restrict file system and network access, and it integrates with a PostgreSQL database to manage and enforce policies.

## Features

- **Policy Enforcement**: Restricts application access to specific files and network ports.
- **Database Integration**: Stores and retrieves policies from a PostgreSQL database.
- **Logging**: Records denied operations and policy updates.
- **Interactive Mode**: Allows users to update policies based on denied operations.

## Prerequisites

- Rust toolchain (stable version)
- PostgreSQL database
- Landlock kernel support

## Building the Project

To build the Supernanny Sandboxer, follow these steps:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/CODE-XANA/SupperNanny.git
   cd supernanny
   ```

2. **Build the Project**:

   ```rust
   cargo build --release
   ```

   This will compile the project and place the binary in the `target/release` directory.

## Running the Sandboxer

To run an application under the Sandboxer, use the following command:

```rust
cargo run --bin sandboxer_db -- <APP> [ARGS...]
```

- Replace `<APP>` with the name of the application you want to sandbox.
- `[ARGS...]` are the arguments you want to pass to the application.

## Testing

The project includes unit tests to verify the functionality of the Sandboxer. To run the tests, use:

```bash
cargo test
```

### Test Coverage

- **Policy Management**: Tests default policy creation and policy updates.
- **Database Interaction**: Verifies policy storage and retrieval from the PostgreSQL database.
- **Log Parsing**: Ensures denied operations are correctly identified from log files.

## Configuration

The Sandboxer uses environment variables to configure the policy for child processes:

- `LL_FS_RO`: Colon-separated list of read-only paths.
- `LL_FS_RW`: Colon-separated list of read-write paths.
- `LL_TCP_BIND`: Colon-separated list of TCP bind ports.
- `LL_TCP_CONNECT`: Colon-separated list of TCP connect ports.

## Database Setup

Ensure your PostgreSQL database is set up with the necessary tables:

```sql
CREATE TABLE app_policy (
    app_name VARCHAR PRIMARY KEY,
    default_ro TEXT,
    default_rw TEXT,
    tcp_bind TEXT,
    tcp_connect TEXT,
    updated_at TIMESTAMP
);

CREATE TABLE sandbox_events (
    event_id SERIAL PRIMARY KEY,
    hostname VARCHAR,
    app_name VARCHAR,
    denied_path TEXT,
    operation VARCHAR,
    result VARCHAR,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Additional Modules

Supernanny includes additional modules such as:

- **User Interface**: Provides a user-friendly interface for managing policies and monitoring sandboxed applications.
- **Network Security**: Enhances security by monitoring and controlling network access.

## License

This project is done with ISEN Méditérannée
