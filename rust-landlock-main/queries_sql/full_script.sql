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
DROP TABLE IF EXISTS user_admin              CASCADE;
DROP TABLE IF EXISTS permission_admin        CASCADE;
DROP TABLE IF EXISTS role_permissions_admin  CASCADE;
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


CREATE TABLE user_admin (
  user_admin_id SERIAL PRIMARY KEY,
  username_admin VARCHAR(255) NOT NULL UNIQUE,
  password_hash_admin VARCHAR(255) NOT NULL
);

CREATE TABLE permission_admin (
  permission_admin_id SERIAL PRIMARY KEY,
  permission_admin_name VARCHAR(255) NOT NULL UNIQUE 
);

CREATE TABLE role_permissions_admin (
  user_admin_id INTEGER NOT NULL,
  permission_admin_id INTEGER NOT NULL,
  PRIMARY KEY (user_admin_id, permission_admin_id),
  FOREIGN KEY (user_admin_id) REFERENCES user_admin(user_admin_id) ON DELETE CASCADE,
  FOREIGN KEY (permission_admin_id) REFERENCES permission_admin(permission_admin_id) ON DELETE CASCADE
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
  (1, 'admin'),
  (2, 'developer'),
  (3, 'user');

INSERT INTO permissions (permission_id, permission_name) VALUES
  (1, 'manage_rules'),
  (2, 'manage_users'),
  (3, 'manage_policies'),
  (4, 'view_events'),
  (5, 'execute_apps');


INSERT INTO role_permissions (role_id, permission_id) VALUES
  (1, 1), (1, 2), (1, 3), (1, 4), (1, 5),
  (2, 2), (2, 3),
  (3, 3);

INSERT INTO users (user_id, username, password_hash) VALUES
  (1, 'admin', '$2a$12$Gp.L8taKXJqc/N/T40fbyekjONH1PaioOfDcvHkubYVDOurNXRoPi'),
  (2, 'developer','$2a$12$OtLIa4HYtsp3nnbx4zQYjOpID.eohUtJYbf5Vu.tgS/hZZ0XLgEVe'),
  (3, 'regular', '$2a$12$tfr8QKoe8jy66nlHXOIlMeAHfxn5vj7inaLuBco3eiDmAJJVEDdBy'),
  (4, 'reviewer', '$2a$12$uSLo1q6uaGrXXdkBRxbTy.ugy1nW7Q2uhXtnZXV9AviPa8kcWGbF.');

INSERT INTO user_roles (user_id, role_id) VALUES
  (1, 1), (2, 2), (3, 3), (4, 1);

INSERT INTO user_admin (user_admin_id, username_admin, password_hash_admin) VALUES
  (1, 'admin_rules', '$argon2id$v=19$m=19456,t=2,p=1$e3gpoTCPNwVJQYGTXTd76w$FPS4FZSOeuD+PNAuriJjXcVZreDb01NvbfEw9cUHklY'),
  (2, 'admin_users', '$argon2id$v=19$m=19456,t=2,p=1$OJqOCTakCBs/zJB8Cyutww$AzrtzQXoyHX5ghpuCN1or1e6l59gLuKKpnhLhdVAEGM'),
  (3, 'admin_roles', '$argon2id$v=19$m=19456,t=2,p=1$AT0LbYjEISg+MzfWfVde7g$4zM6ieWnemMNXP06kZKuZ69O4Fo90uJaDLFZQ9xRbak'),
  (4, 'admin_events', '$argon2id$v=19$m=19456,t=2,p=1$mB/qoTOgPDjRQP9uD72NLA$aO4FKrit2ulzTP1bXqIQ2hUOUAVMF8TAi9JZvEqUwr8');

INSERT INTO permission_admin (permission_admin_id, permission_admin_name) VALUES
  (1, 'manage_rules'),
  (2, 'manage_users'),
  (3, 'manage_roles'),
  (4, 'view_events');

  INSERT INTO role_permissions_admin (user_admin_id, permission_admin_id) VALUES
  (1, 1),
  (2, 2),
  (3, 3),
  (4, 4);

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
