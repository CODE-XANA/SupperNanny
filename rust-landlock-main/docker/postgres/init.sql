CREATE TABLE IF NOT EXISTS app_policy (
    app_name TEXT PRIMARY KEY,
    default_ro TEXT NOT NULL,
    default_rw TEXT NOT NULL,
    tcp_bind TEXT NOT NULL,
    tcp_connect TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sandbox_events (
    event_id SERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    app_name TEXT NOT NULL,
    denied_path TEXT NOT NULL,
    operation TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
