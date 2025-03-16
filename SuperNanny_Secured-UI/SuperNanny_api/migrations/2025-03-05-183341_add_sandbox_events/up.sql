CREATE TABLE sandbox_events (
    event_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    app_name TEXT NOT NULL,
    denied_path TEXT,
    operation TEXT NOT NULL,
    result TEXT NOT NULL
);
