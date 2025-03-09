// @generated automatically by Diesel CLI.

diesel::table! {
    app_policy (app_name) {
        app_name -> Text,
        default_ro -> Text,
        default_rw -> Text,
        tcp_bind -> Text,
        tcp_connect -> Text,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    sandbox_events (event_id) {
        event_id -> Int4,
        timestamp -> Timestamp,
        hostname -> Text,
        app_name -> Text,
        denied_path -> Nullable<Text>,
        operation -> Text,
        result -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    app_policy,
    sandbox_events,
);
