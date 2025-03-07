CREATE TABLE app_policy (
    app_name TEXT PRIMARY KEY,
    default_ro TEXT NOT NULL,
    default_rw TEXT NOT NULL,
    tcp_bind TEXT NOT NULL,
    tcp_connect TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);