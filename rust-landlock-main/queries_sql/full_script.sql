-- ====================================
-- sandboxdb_full_setup.sql
-- Creates and seeds the full database
-- ====================================

-- OPTIONAL: Uncomment to create DB if not already created
-- CREATE DATABASE sandboxdb;
-- \c sandboxdb;

-- ========== DROP TABLES IF EXIST (for reset) ==========
DROP TABLE IF EXISTS sandbox_events CASCADE;
DROP TABLE IF EXISTS app_policy CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS default_policies CASCADE;

-- ========== TABLES ==========

-- Users
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

-- Roles
CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name TEXT NOT NULL UNIQUE
);

-- User-Roles
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- Permissions
CREATE TABLE permissions (
    permission_id SERIAL PRIMARY KEY,
    permission_name TEXT NOT NULL UNIQUE
);

-- Role-Permissions
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

-- App Policy (with network rules)
CREATE TABLE app_policy (
    policy_id SERIAL PRIMARY KEY,
    app_name TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    default_ro TEXT NOT NULL,
    default_rw TEXT NOT NULL,
    tcp_bind TEXT NOT NULL,
    tcp_connect TEXT NOT NULL,
    allowed_ips TEXT NOT NULL,
    allowed_domains TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (app_name, role_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- Default Policies
CREATE TABLE default_policies (
    role_id INTEGER PRIMARY KEY,
    default_ro TEXT NOT NULL,
    default_rw TEXT NOT NULL,
    tcp_bind TEXT NOT NULL,
    tcp_connect TEXT NOT NULL,
    allowed_ips TEXT NOT NULL,
    allowed_domains TEXT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

-- Sandbox Events (logs, with optional user and network fields)
CREATE TABLE sandbox_events (
    event_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    app_name TEXT NOT NULL,
    denied_path TEXT,
    operation TEXT NOT NULL,
    result TEXT NOT NULL,
    user_id INTEGER,
    remote_ip TEXT,
    domain TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- ========== SEED DATA ==========

-- Roles
INSERT INTO roles (role_id, role_name) VALUES
  (1, 'admin'),
  (2, 'developer'),
  (3, 'user');

-- Permissions
INSERT INTO permissions (permission_id, permission_name) VALUES
  (1, 'manage_policies'),
  (2, 'view_events'),
  (3, 'execute_apps'),
  (4, 'view_policies');

-- Role-Permissions
INSERT INTO role_permissions (role_id, permission_id) VALUES
  (1, 1),
  (1, 2),
  (1, 3),
  (1, 4),
  (2, 2),
  (2, 3),
  (3, 3);

-- Users
INSERT INTO users (user_id, username, password_hash) VALUES
  (1, 'admin',     '$2a$12$Gp.L8taKXJqc/N/T40fbyekjONH1PaioOfDcvHkubYVDOurNXRoPi'),
  (2, 'developer', '$2a$12$OtLIa4HYtsp3nnbx4zQYjOpID.eohUtJYbf5Vu.tgS/hZZ0XLgEVe'),
  (3, 'regular',   '$2a$12$tfr8QKoe8jy66nlHXOIlMeAHfxn5vj7inaLuBco3eiDmAJJVEDdBy');

-- User Roles
INSERT INTO user_roles (user_id, role_id) VALUES
  (1, 1),
  (2, 2),
  (3, 3);

-- Default Policies for Roles
INSERT INTO default_policies (role_id, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains) VALUES
  (1, '/bin:/usr:/dev/urandom:/etc:/proc:/lib', '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null', '9418', '80:443', '127.0.0.1/8:192.168.1.0/24', 'localhost:example.com'),
  (2, '/bin:/usr:/dev/urandom:/etc:/proc:/lib', '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null', '9418', '80:443', '127.0.0.1/8:192.168.1.0/24', 'localhost:developer.com'),
  (3, '/bin:/usr:/dev/urandom:/etc:/proc:/lib', '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null', '9418', '80:443', '127.0.0.1/8:192.168.1.0/24', 'localhost:user.com');

-- App Policy: /bin/firefox for developer
INSERT INTO app_policy (
  app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains, updated_at
) VALUES (
  '/bin/firefox',
  2,
  '/bin:/usr:/dev/urandom:/etc:/proc:/lib:/dev/dri:/dev/snd:/dev/fb0',
  '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null:/dev/shm:/run/user/1000/pulse:/home/alexandre/.cache:/var:/proc:/home/alexandre/.config:/sys:/home/alexandre/.mozilla:/run/user/1000:/home/alexandre/.Xauthority:/run/resolvconf:/dev/dri',
  '9418',
  '80:443',
  '127.0.0.1/8:192.168.1.0/24',
  'localhost:mozilla.org:firefox.com',
  NOW()
);

-- App Policy: /bin/ping (allow ONLY 127.0.0.1)
INSERT INTO app_policy (
  app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains, updated_at
) VALUES (
  '/bin/ping',
  2,
  '/bin:/usr:/etc:/proc:/lib:/dev',
  '/tmp',
  '0',
  '0',
  '127.0.0.1/32',
  'localhost',
  NOW()
);

-- Reset sequences (if needed)
SELECT setval('roles_role_id_seq', (SELECT MAX(role_id) FROM roles));
SELECT setval('permissions_permission_id_seq', (SELECT MAX(permission_id) FROM permissions));
SELECT setval('users_user_id_seq', (SELECT MAX(user_id) FROM users));
SELECT setval('app_policy_policy_id_seq', (SELECT MAX(policy_id) FROM app_policy));
SELECT setval('sandbox_events_event_id_seq', (SELECT COALESCE(MAX(event_id), 1) FROM sandbox_events));
