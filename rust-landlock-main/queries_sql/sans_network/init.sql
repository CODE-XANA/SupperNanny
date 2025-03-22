-- Create the database (optional)
CREATE DATABASE sandboxdb;
\c sandboxdb; -- Connect to the database

-- Users Table
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

-- Roles Table
CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name TEXT NOT NULL UNIQUE
);

-- User Roles (Many-to-Many)
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- Permissions Table
CREATE TABLE permissions (
    permission_id SERIAL PRIMARY KEY,
    permission_name TEXT NOT NULL UNIQUE
);

-- Role Permissions (Many-to-Many)
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

-- Application Policy Table (Linked to Roles)
CREATE TABLE app_policy (
    policy_id SERIAL PRIMARY KEY,
    app_name TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    default_ro TEXT NOT NULL,
    default_rw TEXT NOT NULL,
    tcp_bind TEXT NOT NULL,
    tcp_connect TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (app_name, role_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- Sandbox Events (Logs Table) (Linked to Users)
CREATE TABLE sandbox_events (
    event_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    app_name TEXT NOT NULL,
    denied_path TEXT,
    operation TEXT NOT NULL,
    result TEXT NOT NULL,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);
