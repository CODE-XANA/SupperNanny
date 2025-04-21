use axum::{
    extract::{Extension, Json, Query, Path},
    http::StatusCode,
};
use std::collections::HashMap;
use postgres::types::ToSql;
use std::sync::Arc;

use crate::{
    auth::jwt::AuthUser,
    models::dto::{
        AppPolicyCreateRequest,
        PolicyChangeRequest,
        PolicyRequestDetail,
        PolicyRequestDecision
    },
    state::AppState,
    utils::permissions::has_permission,
};
use tokio::task::spawn_blocking;
use std::collections::HashSet;

pub async fn add_app_policy(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
    Json(body): Json<AppPolicyCreateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !has_permission(Arc::new(state.clone()), claims.user_id, "manage_policies").await? {
        return Err((StatusCode::FORBIDDEN, "Permission denied".to_string()));
    }

    // Clone everything we'll need in the blocking task
    let app_name = body.app_name.clone();
    let role_id = body.role_id;
    let default_ro = body.default_ro.clone();
    let default_rw = body.default_rw.clone();
    let tcp_bind = body.tcp_bind.clone();
    let tcp_connect = body.tcp_connect.clone();
    let allowed_ips = body.allowed_ips.clone();
    let allowed_domains = body.allowed_domains.clone();
    
    // Get a pool we can move into the blocking task
    let pool = state.db_pool.clone();
    
    spawn_blocking(move || {
        let mut conn = pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        conn.execute(
            "
            INSERT INTO app_policy (
                app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect,
                allowed_ips, allowed_domains, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (app_name, role_id)
            DO UPDATE SET
                default_ro = EXCLUDED.default_ro,
                default_rw = EXCLUDED.default_rw,
                tcp_bind = EXCLUDED.tcp_bind,
                tcp_connect = EXCLUDED.tcp_connect,
                allowed_ips = EXCLUDED.allowed_ips,
                allowed_domains = EXCLUDED.allowed_domains,
                updated_at = NOW()
            ",
            &[
                &app_name,
                &role_id,
                &default_ro,
                &default_rw,
                &tcp_bind,
                &tcp_connect,
                &allowed_ips,
                &allowed_domains,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Insert error: {e}")))?;

        Ok::<_, (StatusCode, String)>(())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Task join error".to_string()))??;

    Ok(StatusCode::CREATED)
}

pub async fn request_policy_change(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
    Json(request): Json<PolicyChangeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !has_permission(Arc::new(state.clone()), claims.user_id, "manage_policies").await? {
        return Err((StatusCode::FORBIDDEN, "Permission denied".to_string()));
    }

    // Clone all the data we need to move into the blocking task
    let app_name = request.app_name.clone();
    let role_id = request.role_id;
    let user_id = claims.user_id;
    let default_ro = request.default_ro.clone();
    let default_rw = request.default_rw.clone();
    let tcp_bind = request.tcp_bind.clone();
    let tcp_connect = request.tcp_connect.clone();
    let allowed_ips = request.allowed_ips.clone();
    let allowed_domains = request.allowed_domains.clone();
    let allowed_ro_paths = request.allowed_ro_paths.clone();
    let allowed_rw_paths = request.allowed_rw_paths.clone();
    let change_justification = request.change_justification.clone();
    
    // Clone the pool to move it
    let pool = state.db_pool.clone();
    
    spawn_blocking(move || {
        let mut conn = pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        let has_role = conn.query_one(
            "SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)",
            &[&user_id, &role_id]
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query error: {e}")))?
        .get::<_, bool>(0);

        if !has_role {
            return Err((StatusCode::FORBIDDEN, "You can only request changes for roles you belong to".to_string()));
        }

        conn.execute(
            "INSERT INTO policy_change_requests (
                app_name, role_id, requested_by, status,
                default_ro, default_rw, tcp_bind, tcp_connect,
                allowed_ips, allowed_domains,
                allowed_ro_paths, allowed_rw_paths,
                change_justification
            ) VALUES (
                $1, $2, $3, 'pending',
                $4, $5, $6, $7,
                $8, $9,
                $10, $11,
                $12
            )",
            &[
                &app_name,
                &role_id,
                &user_id,
                &default_ro,
                &default_rw,
                &tcp_bind,
                &tcp_connect,
                &allowed_ips,
                &allowed_domains,
                &allowed_ro_paths,
                &allowed_rw_paths,
                &change_justification,
            ]
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Insert error: {e}")))?;

        // Log it - note we need to create a string compatible with &str for the query
        let detail = format!(
            "Requested policy change for app {} for role ID {}",
            app_name, role_id
        );
        
        conn.execute(
            "INSERT INTO security_logs (username, action, detail, severity)
             SELECT u.username, 'policy_change_requested', $1, 'info'
             FROM users u WHERE u.user_id = $2",
            &[&detail, &user_id]
        ).ok();

        Ok::<_, (StatusCode, String)>(())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Task join error".to_string()))??;

    Ok(StatusCode::CREATED)
}

pub async fn get_policy_requests(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<PolicyRequestDetail>>, (StatusCode, String)> {
    if !has_permission(Arc::new(state.clone()), claims.user_id, "approve_policies").await? {
        return Err((StatusCode::FORBIDDEN, "Permission denied".to_string()));
    }

    // Clone params and whatever else we need
    let params_clone = params.clone();
    let _user_id = claims.user_id;
    let pool = state.db_pool.clone();
    
    let requests = spawn_blocking(move || {
        let mut conn = pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        let mut query = String::from(
            "SELECT 
                pcr.request_id, pcr.app_name, pcr.role_id, r.role_name,
                u.username as requested_by, pcr.requested_at::text, 
                pcr.status::text, -- Cast enum to text
                pcr.default_ro, pcr.default_rw, pcr.tcp_bind, pcr.tcp_connect,
                pcr.allowed_ips, pcr.allowed_domains, pcr.change_justification
             FROM policy_change_requests pcr
             JOIN roles r ON pcr.role_id = r.role_id
             JOIN users u ON pcr.requested_by = u.user_id
             WHERE 1=1"
        );

        let mut params_vec: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        let mut param_index = 1;

        if let Some(status) = params_clone.get("status") {
            query.push_str(&format!(" AND pcr.status::text = ${}", param_index));
            params_vec.push(Box::new(status.clone()));
            param_index += 1;
        }

        // Handle role_id: parse it first, then add to query and params if valid
        if let Some(role_id_str) = params_clone.get("role_id") {
            if let Ok(role_id) = role_id_str.parse::<i32>() {
                query.push_str(&format!(" AND pcr.role_id = ${}", param_index));
                params_vec.push(Box::new(role_id));
                param_index += 1;
            }
        }

        if let Some(app_name) = params_clone.get("app_name") {
            query.push_str(&format!(" AND pcr.app_name = ${}", param_index));
            params_vec.push(Box::new(app_name.clone()));
        }

        query.push_str(" ORDER BY pcr.requested_at DESC");

        // Convert params_vec to a slice of references that postgres can use
        let param_refs: Vec<&(dyn ToSql + Sync)> = params_vec
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();

        let rows = conn.query(&query, &param_refs[..])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query error: {e}")))?;
        
        tracing::info!("Fetched {} rows from DB", rows.len());
        let requests: Vec<PolicyRequestDetail> = rows.iter().map(|row| {
            PolicyRequestDetail {
                request_id: row.get("request_id"),
                app_name: row.get("app_name"),
                role_id: row.get("role_id"),
                role_name: row.get("role_name"),
                requested_by: row.get("requested_by"),
                requested_at: row.get("requested_at"),
                status: row.get("status"),
                default_ro: row.get("default_ro"),
                default_rw: row.get("default_rw"),
                tcp_bind: row.get("tcp_bind"),
                tcp_connect: row.get("tcp_connect"),
                allowed_ips: row.get("allowed_ips"),
                allowed_domains: row.get("allowed_domains"),
                change_justification: row.get("change_justification"),
            }
        }).collect();
        tracing::info!("Returning {} requests", requests.len());
        Ok::<_, (StatusCode, String)>(requests)
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Task join error".to_string()))??;

    Ok(Json(requests))
}

pub async fn process_policy_request(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
    Path(request_id): Path<i32>,
    Json(decision): Json<PolicyRequestDecision>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !has_permission(Arc::new(state.clone()), claims.user_id, "approve_policies").await? {
        return Err((StatusCode::FORBIDDEN, "Permission denied".to_string()));
    }

    let user_id = claims.user_id;
    let pool = state.db_pool.clone();

    spawn_blocking(move || {
        let mut conn = pool.get().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        conn.execute("BEGIN", &[]).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {e}")))?;

        let request = conn.query_opt(
            "SELECT request_id, app_name, role_id, requested_by, 
                    default_ro, default_rw, tcp_bind, tcp_connect,
                    allowed_ips, allowed_domains
             FROM policy_change_requests 
             WHERE request_id = $1 AND status = 'pending'",
            &[&request_id]
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query error: {e}")))?;

        let row = match request {
            Some(row) => row,
            None => return Err((StatusCode::NOT_FOUND, "Request not found or already processed".to_string())),
        };

        let requested_by: i32 = row.get("requested_by");
        if requested_by == user_id {
            return Err((StatusCode::FORBIDDEN, "Cannot approve your own policy change requests".to_string()));
        }

        let app_name: String = row.get("app_name");
        let role_id: i32 = row.get("role_id");
        let new_ro: String = row.get("default_ro");
        let new_rw: String = row.get("default_rw");
        let new_bind: String = row.get("tcp_bind");
        let new_connect: String = row.get("tcp_connect");
        let new_ips: String = row.get("allowed_ips");
        let new_domains: String = row.get("allowed_domains");

        // Merge function for colon-separated values
        let merge_colon_strings = |existing: String, new: String| -> String {
            let mut set: HashSet<&str> = existing.split(':').filter(|s| !s.is_empty()).collect();
            for val in new.split(':').filter(|s| !s.is_empty()) {
                set.insert(val);
            }
            let mut merged: Vec<&str> = set.into_iter().collect();
            merged.sort();
            merged.join(":")
        };

        let (final_ro, final_rw, final_bind, final_connect, final_ips, final_domains) =
            if let Some(existing_row) = conn.query_opt(
                "SELECT default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
                 FROM app_policy WHERE app_name = $1 AND role_id = $2",
                &[&app_name, &role_id]
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Fetch existing policy error: {e}")))? {
                (
                    merge_colon_strings(existing_row.get("default_ro"), new_ro),
                    merge_colon_strings(existing_row.get("default_rw"), new_rw),
                    merge_colon_strings(existing_row.get("tcp_bind"), new_bind),
                    merge_colon_strings(existing_row.get("tcp_connect"), new_connect),
                    merge_colon_strings(existing_row.get("allowed_ips"), new_ips),
                    merge_colon_strings(existing_row.get("allowed_domains"), new_domains),
                )
            } else {
                (new_ro, new_rw, new_bind, new_connect, new_ips, new_domains)
            };

        if decision.approve {
            conn.execute(
                "INSERT INTO app_policy (
                    app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect,
                    allowed_ips, allowed_domains, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                ON CONFLICT (app_name, role_id)
                DO UPDATE SET
                    default_ro = $3,
                    default_rw = $4,
                    tcp_bind = $5,
                    tcp_connect = $6,
                    allowed_ips = $7,
                    allowed_domains = $8,
                    updated_at = NOW()",
                &[&app_name, &role_id, &final_ro, &final_rw, &final_bind, &final_connect, &final_ips, &final_domains]
            ).map_err(|e| {
                let _ = conn.execute("ROLLBACK", &[]);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Policy update error: {e}"))
            })?;

            conn.execute(
                "UPDATE policy_change_requests SET status = 'approved', reviewed_by = $1, reviewed_at = NOW() WHERE request_id = $2",
                &[&user_id, &request_id]
            ).map_err(|e| {
                let _ = conn.execute("ROLLBACK", &[]);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Status update error: {e}"))
            })?;

            let detail = format!("Approved policy change request #{} for app {} and role {}", request_id, app_name, role_id);
            conn.execute(
                "INSERT INTO security_logs (username, action, detail, severity)
                 SELECT u.username, 'policy_change_approved', $1, 'info'
                 FROM users u WHERE u.user_id = $2",
                &[&detail, &user_id]
            ).ok();
        } else {
            conn.execute(
                "UPDATE policy_change_requests SET status = 'rejected', reviewed_by = $1, reviewed_at = NOW() WHERE request_id = $2",
                &[&user_id, &request_id]
            ).map_err(|e| {
                let _ = conn.execute("ROLLBACK", &[]);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Rejection update error: {e}"))
            })?;

            let reason = decision.reason.clone().unwrap_or_else(|| "No reason provided".to_string());
            let detail = format!("Rejected policy change request #{} with reason: {}", request_id, reason);
            conn.execute(
                "INSERT INTO security_logs (username, action, detail, severity)
                 SELECT u.username, 'policy_change_rejected', $1, 'warning'
                 FROM users u WHERE u.user_id = $2",
                &[&detail, &user_id]
            ).ok();
        }

        conn.execute("COMMIT", &[]).map_err(|e| {
            let _ = conn.execute("ROLLBACK", &[]);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Commit error: {e}"))
        })?;

        Ok::<_, (StatusCode, String)>(())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Task join error".to_string()))??;

    Ok(StatusCode::OK)
}