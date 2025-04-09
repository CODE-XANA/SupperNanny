use serde::Serialize;

#[derive(Serialize)]
pub struct RuleSet {
    pub ro_paths: Vec<String>,
    pub rw_paths: Vec<String>,
    pub tcp_bind: Vec<u16>,
    pub tcp_connect: Vec<u16>,
    pub allowed_ips: Vec<String>,
    pub allowed_domains: Vec<String>,
}
