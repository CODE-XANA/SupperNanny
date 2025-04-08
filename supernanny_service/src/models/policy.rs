use serde::Serialize;

#[derive(Serialize)]
pub struct Policy {
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
}

#[derive(Serialize)]
pub struct AppRuleSet {
    pub app_name: String,
    pub policy: Policy,
}

#[derive(Serialize)]
pub struct RuleSetResponse {
    pub default_policies: Vec<Policy>,
    pub app_policies: Vec<AppRuleSet>,
}
