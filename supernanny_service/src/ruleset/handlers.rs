use axum::{
    extract::Extension,
    http::StatusCode,
    Json,
};

use crate::{
    auth::jwt::AuthUser,
    models::policy::RuleSetResponse,
    ruleset::{default::get_default_rules, app_name::get_app_rules},
    state::AppState,
};

/// Returns a combined set of default and application-specific policies for the authenticated user.
pub async fn get_ruleset(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
) -> Result<Json<RuleSetResponse>, (StatusCode, String)> {
    let role_id = claims.role_id;

    // Get default policies
    let default = get_default_rules(Extension(state.clone()), role_id).await?;
    
    // Get application-specific policies
    let app = get_app_rules(Extension(state), role_id).await?;

    Ok(Json(RuleSetResponse {
        default_policies: default.0,
        app_policies: app.0,
    }))
}
