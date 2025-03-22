-- ---------------------------------------------
-- sandboxdb_seed.sql
-- Inserts seed data into the sandboxdb database
-- ---------------------------------------------

-- Insert Roles
INSERT INTO roles (role_id, role_name) VALUES
  (1, 'admin'),
  (2, 'developer'),
  (3, 'user');

-- Insert Permissions
INSERT INTO permissions (permission_id, permission_name) VALUES
  (1, 'manage_policies'),
  (2, 'view_events'),
  (3, 'execute_apps'),
  (4, 'view_policies');

-- Insert Role-Permissions
INSERT INTO role_permissions (role_id, permission_id) VALUES
  (1, 1),
  (1, 2),
  (1, 3),
  (1, 4),
  (2, 2),
  (2, 3),
  (3, 3);

-- Insert Users
INSERT INTO users (user_id, username, password_hash) VALUES
  (1, 'admin',     '$2a$12$NzDv/E0QM5N2vCtqqpqJeeVvQ6OIJYCs22Z1L7j8wIHpcxJXYKAJO'),
  (2, 'developer', '$2a$12$yBBX3U8PoI1VGX9arthf4e4iqJjB9uzhcYAetUVSJt32qe97DGYNu'),
  (3, 'regular',   '$2a$12$nmuZC4yuHPlN8EXY6FcfY.KR6o7bZoOE/J0W07EnBJmXdHDTmPC22');

-- Insert User Roles
INSERT INTO user_roles (user_id, role_id) VALUES
  (1, 1),
  (2, 2),
  (3, 3);

-- Optional: Example App Policy for developer
-- Comment out if you want app_policy to remain empty
INSERT INTO app_policy (
  app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect, updated_at
) VALUES (
  '/bin/ls',
  2,
  '/bin:/usr:/dev/urandom:/etc:/proc:/lib',
  '/tmp:/dev/zero:/dev/full:/dev/pts:/dev/null',
  '9418',
  '80:443',
  NOW()
);

-- Reset sequences if using SERIAL/identity
SELECT setval('roles_role_id_seq', (SELECT MAX(role_id) FROM roles));
SELECT setval('permissions_permission_id_seq', (SELECT MAX(permission_id) FROM permissions));
SELECT setval('users_user_id_seq', (SELECT MAX(user_id) FROM users));
