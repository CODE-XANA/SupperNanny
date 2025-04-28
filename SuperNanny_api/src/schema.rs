// @generated automatically by Diesel CLI.

diesel::table! {
    app_policy (policy_id) {
        policy_id -> Int4,
        app_name -> Text,
        role_id -> Int4,
        default_ro -> Text,
        default_rw -> Text,
        tcp_bind -> Text,
        tcp_connect -> Text,
        allowed_ips -> Text,
        allowed_domains -> Text,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    default_policies (role_id) {
        role_id -> Int4,
        default_ro -> Text,
        default_rw -> Text,
        tcp_bind -> Text,
        tcp_connect -> Text,
        allowed_ips -> Text,
        allowed_domains -> Text,
    }
}

diesel::table! {
    permissions (permission_id) {
        permission_id -> Int4,
        permission_name -> Text,
    }
}

diesel::table! {
    role_permissions (role_id, permission_id) {
        role_id -> Int4,
        permission_id -> Int4,
    }
}

diesel::table! {
    roles (role_id) {
        role_id -> Int4,
        role_name -> Text,
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
        user_id -> Nullable<Int4>,
        remote_ip -> Nullable<Text>,
        domain -> Nullable<Text>,
    }
}

diesel::table! {
    user_roles (user_id, role_id) {
        user_id -> Int4,
        role_id -> Int4,
    }
}

diesel::table! {
    users (user_id) {
        user_id -> Int4,
        username -> Text,
        password_hash -> Text,
    }
}

diesel::table! {
    user_admin (user_admin_id) {
        user_admin_id    -> Int4,
        username_admin   -> Varchar,
        password_hash_admin -> Varchar,
    }
}

diesel::table! {
    permission_admin (permission_admin_id) {
        permission_admin_id   -> Int4,
        permission_admin_name -> Varchar,
    }
}

diesel::table! {
    role_permissions_admin (user_admin_id, permission_admin_id) {
        user_admin_id        -> Int4,
        permission_admin_id  -> Int4,
    }
}

diesel::table! {
    security_logs (log_id) {
        log_id      -> Int4,
        timestamp   -> Timestamp,
        username    -> Nullable<Varchar>,
        ip_address  -> Nullable<Varchar>,
        action      -> Varchar,
        detail      -> Nullable<Text>,
        severity    -> Varchar,
    }
}


diesel::joinable!(app_policy -> roles (role_id));
diesel::joinable!(default_policies -> roles (role_id));
diesel::joinable!(role_permissions -> permissions (permission_id));
diesel::joinable!(role_permissions -> roles (role_id));
diesel::joinable!(sandbox_events -> users (user_id));
diesel::joinable!(user_roles -> roles (role_id));
diesel::joinable!(user_roles -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    app_policy,
    default_policies,
    permissions,
    role_permissions,
    roles,
    sandbox_events,
    user_roles,
    users,
    user_admin,
    permission_admin,
    role_permissions_admin,
);