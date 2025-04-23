\set ON_ERROR_STOP on
BEGIN;

-- =========================================================
-- Drops any existing objects, recreates schema and seed data
-- =========================================================

-- ---------- CLEAN SLATE ----------------------------------
DROP TABLE IF EXISTS policy_change_requests  CASCADE;
DROP TABLE IF EXISTS sandbox_events          CASCADE;
DROP TABLE IF EXISTS app_policy              CASCADE;
DROP TABLE IF EXISTS role_permissions        CASCADE;
DROP TABLE IF EXISTS user_roles              CASCADE;
DROP TABLE IF EXISTS permissions             CASCADE;
DROP TABLE IF EXISTS roles                   CASCADE;
DROP TABLE IF EXISTS users                   CASCADE;
DROP TABLE IF EXISTS default_policies        CASCADE;
DROP TABLE IF EXISTS security_logs           CASCADE;
DROP TYPE  IF EXISTS policy_status           CASCADE;
DROP INDEX IF EXISTS unique_app_role_pending;

-- ---------- SCHEMA ---------------------------------------
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name TEXT NOT NULL UNIQUE
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

CREATE TABLE permissions (
    permission_id SERIAL PRIMARY KEY,
    permission_name TEXT NOT NULL UNIQUE
);

CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

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

-- ENUM for request status
CREATE TYPE policy_status AS ENUM ('pending', 'approved', 'rejected');

CREATE TABLE policy_change_requests (
    request_id SERIAL PRIMARY KEY,
    app_name TEXT NOT NULL,
    role_id INTEGER REFERENCES roles(role_id) ON DELETE CASCADE,
    requested_by INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    status policy_status DEFAULT 'pending',

    default_ro TEXT NOT NULL,
    default_rw TEXT NOT NULL,
    tcp_bind TEXT NOT NULL,
    tcp_connect TEXT NOT NULL,
    allowed_ips TEXT NOT NULL,
    allowed_domains TEXT NOT NULL,

    allowed_ro_paths TEXT[] NOT NULL DEFAULT '{}',
    allowed_rw_paths TEXT[] NOT NULL DEFAULT '{}',

    change_justification TEXT NOT NULL,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    reviewed_by INTEGER REFERENCES users(user_id),
    reviewed_at TIMESTAMP
);

CREATE UNIQUE INDEX idx_unique_pending_requests 
ON policy_change_requests (app_name, role_id, requested_by) 
WHERE status = 'pending';

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

CREATE TABLE security_logs (
    log_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    username TEXT,
    ip_address TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical'))
);

-- ---------- SEED DATA ------------------------------------
INSERT INTO roles (role_id, role_name) VALUES
  (1, 'developer_senior'),
  (2, 'developer'),
  (3, 'user');
  (4, 'reviewer')

INSERT INTO permissions (permission_id, permission_name) VALUES
  (1, 'manage_policies'),
  (2, 'view_events'),
  (3, 'execute_apps'),
  (4, 'view_policies'),
  (5, 'approve_policies');

INSERT INTO role_permissions (role_id, permission_id) VALUES
  (1, 1), (1, 2), (1, 3), (1, 4), (1, 5),
  (2, 2), (2, 3),
  (3, 3),
  (4, 4);

INSERT INTO users (user_id, username, password_hash) VALUES
  (1, 'developer_senior',     '$2a$12$Gp.L8taKXJqc/N/T40fbyekjONH1PaioOfDcvHkubYVDOurNXRoPi'),
  (2, 'developer', '$2a$12$OtLIa4HYtsp3nnbx4zQYjOpID.eohUtJYbf5Vu.tgS/hZZ0XLgEVe'),
  (3, 'regular',   '$2a$12$tfr8QKoe8jy66nlHXOIlMeAHfxn5vj7inaLuBco3eiDmAJJVEDdBy'),
  (4, 'reviewer',  '$2a$12$uSLo1q6uaGrXXdkBRxbTy.ugy1nW7Q2uhXtnZXV9AviPa8kcWGbF.');

INSERT INTO user_roles (user_id, role_id) VALUES
  (1, 1), (2, 2), (3, 3), (4, 1);

INSERT INTO default_policies (
  role_id, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
) VALUES
  (1, '/bin:/usr:/dev/urandom:/etc:/proc:/lib', '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null', '9418', '80:443', '127.0.0.1/8:192.168.1.0/24', 'localhost:example.com'),
  (2, '/bin:/usr:/dev/urandom:/etc:/proc:/lib', '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null', '9418', '80:443', '127.0.0.1/8:192.168.1.0/24', 'localhost:developer.com'),
  (3, '/bin:/usr:/dev/urandom:/etc:/proc:/lib', '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null', '9418', '80:443', '127.0.0.1/8:192.168.1.0/24', 'localhost:user.com');

INSERT INTO app_policy (
  app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect,
  allowed_ips, allowed_domains, updated_at
) VALUES
  ('/bin/firefox', 2,
   '/bin:/usr:/dev/urandom:/etc:/proc:/lib:/dev/dri:/dev/snd:/dev/fb0',
   '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null:/dev/shm:/run/user/1000/pulse:/home/alexandre/.cache:/var:/proc:/home/alexandre/.config:/sys:/home/alexandre/.mozilla:/run/user/1000:/home/alexandre/.Xauthority:/run/resolvconf:/dev/dri',
   '9418', '80:443',
   '127.0.0.1/8:192.168.1.0/24',
   'localhost:mozilla.org:firefox.com',
   NOW()),
  ('/bin/ping', 2,
   '/bin:/usr:/etc:/proc:/lib:/dev',
   '/tmp',
   '0', '0',
   '127.0.0.1/32',
   'localhost',
   NOW()),
  ('/bin/ls', 1,
   '/bin:/usr:/etc:/proc:/lib',
   '/tmp',
   '',
   '',
   '127.0.0.1/32',
   'localhost',
   NOW()),
  ('/bin/ls', 2,
   '/bin:/usr:/etc:/proc:/lib',
   '/tmp',
   '',
   '',
   '127.0.0.1/32',
   'localhost',
   NOW());


-- ---------- SEQUENCE ALIGNMENT ---------------------------
SELECT setval('roles_role_id_seq',             (SELECT MAX(role_id) FROM roles));
SELECT setval('permissions_permission_id_seq', (SELECT MAX(permission_id) FROM permissions));
SELECT setval('users_user_id_seq',             (SELECT MAX(user_id) FROM users));
SELECT setval('app_policy_policy_id_seq',      (SELECT MAX(policy_id) FROM app_policy));
SELECT setval('sandbox_events_event_id_seq',   COALESCE((SELECT MAX(event_id) FROM sandbox_events),1));

COMMIT;