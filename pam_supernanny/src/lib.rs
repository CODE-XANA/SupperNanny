use pam_sys::PamHandle;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;
use reqwest::blocking::Client;
use anyhow::{anyhow, Result};

// PAM constants
const PAM_USER: c_int = 2;
const PAM_AUTHTOK: c_int = 5;
const PAM_OLDAUTHTOK: c_int = 6;
const PAM_CONV: c_int = 10;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

// Token cache settings
const TOKEN_CACHE_DIR: &str = "supernanny";
const TOKEN_CACHE_FILE: &str = "session.cache";
const TOKEN_VALIDITY_HOURS: u64 = 8;

// Add logging macro
macro_rules! pam_log {
    ($level:expr, $($arg:tt)*) => {
        {
            use std::io::Write;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let msg = format!("[{}] PAM_SUPERNANNY {}: {}\n", 
                timestamp, $level, format!($($arg)*));
            
            // Try to write to syslog via logger command
            let _ = std::process::Command::new("logger")
                .arg("-p")
                .arg("auth.info")
                .arg("-t")
                .arg("pam_supernanny")
                .arg(&msg.trim())
                .output();
            
            // Also try to write to a debug file
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/pam_supernanny.log") {
                let _ = file.write_all(msg.as_bytes());
            }
        }
    };
}

#[derive(Serialize, Deserialize, Clone)]
struct CachedToken {
    token: String,
    username: String,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

impl CachedToken {
    fn new(token: String, username: String, refresh_token: Option<String>) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + TOKEN_VALIDITY_HOURS * 3600;
        Self { token, username, expires_at, refresh_token }
    }

    fn is_expired(&self) -> bool {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() >= self.expires_at
    }

    fn is_near_expiry(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        (self.expires_at - now) < 1800 // 30 minutes
    }
}

impl Drop for CachedToken {
    fn drop(&mut self) {
        self.token.zeroize();
        if let Some(ref mut refresh) = self.refresh_token {
            refresh.zeroize();
        }
    }
}

// PAM structures
#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type PamConvFunc = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: PamConvFunc,
    appdata_ptr: *mut c_void,
}

fn parse_pam_args(argc: i32, argv: *const *const c_char) -> Vec<String> {
    let mut args = Vec::new();
    if argc > 0 && !argv.is_null() {
        unsafe {
            for i in 0..argc {
                let arg_ptr = *argv.add(i as usize);
                if !arg_ptr.is_null() {
                    if let Ok(arg_cstr) = CStr::from_ptr(arg_ptr).to_str() {
                        args.push(arg_cstr.to_string());
                    }
                }
            }
        }
    }
    args
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: i32,
    argc: i32,
    argv: *const *const c_char,
) -> i32 {
    pam_log!("INFO", "PAM module called");
    
    let args = parse_pam_args(argc, argv);
    pam_log!("DEBUG", "PAM args: {:?}", args);
    
    match handle_authenticate(pamh, &args) {
        Ok(_) => {
            pam_log!("INFO", "Authentication successful");
            0  // PAM_SUCCESS
        },
        Err(e) => {
            pam_log!("ERROR", "Authentication failed: {}", e);
            7 // PAM_AUTH_ERR
        }
    }
}

fn handle_authenticate(pamh: *mut PamHandle, args: &[String]) -> Result<()> {
    let username = get_pam_user(pamh)?;
    pam_log!("INFO", "Authenticating user: {}", username);
    
    let uid = get_user_uid(&username)?;
    pam_log!("DEBUG", "User UID: {}", uid);
    
    let use_first_pass = args.iter().any(|arg| arg == "use_first_pass");
    pam_log!("DEBUG", "use_first_pass: {}", use_first_pass);

    // Check if we should skip server authentication (debug mode)
    let debug_mode = args.iter().any(|arg| arg == "debug_skip_server");
    if debug_mode {
        pam_log!("INFO", "Debug mode: skipping server authentication");
        return Ok(());
    }

    // Check cached token first
    if let Ok(cached) = load_cached_token(uid) {
        pam_log!("DEBUG", "Found cached token for user: {}", cached.username);
        if !cached.is_expired() && cached.username == username {
            pam_log!("INFO", "Using valid cached token");
            return Ok(());
        }
        if cached.is_near_expiry() {
            pam_log!("DEBUG", "Token near expiry, attempting refresh");
            if let Some(rt) = &cached.refresh_token {
                if let Ok(new) = refresh_auth_token(rt, &username) {
                    save_cached_token(uid, &new)?;
                    pam_log!("INFO", "Token refreshed successfully");
                    return Ok(());
                }
            }
        }
        pam_log!("DEBUG", "Cached token expired or invalid");
    } else {
        pam_log!("DEBUG", "No cached token found");
    }

    // Get password
    pam_log!("DEBUG", "Getting password from PAM");
    let password = if use_first_pass {
        get_pam_password_with_fallback(pamh)?
    } else {
        match get_pam_password_with_fallback(pamh) {
            Ok(pass) => pass,
            Err(e) => {
                pam_log!("DEBUG", "Failed to get password from PAM tokens: {}, trying conversation", e);
                get_password_via_conversation(pamh)?
            }
        }
    };
    
    pam_log!("DEBUG", "Password obtained, authenticating with server");
    let token = authenticate_with_server(&username, &password)?;
    save_cached_token(uid, &token)?;
    pam_log!("INFO", "Server authentication successful, token cached");
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: i32,
    _argc: i32,
    _argv: *const *const c_char,
) -> i32 {
    pam_log!("DEBUG", "pam_sm_setcred called");
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: i32,
    _argc: i32,
    _argv: *const *const c_char,
) -> i32 {
    pam_log!("DEBUG", "pam_sm_open_session called");
    match handle_session_open(pamh) {
        Ok(_) => {
            pam_log!("INFO", "Session opened successfully");
            0
        },
        Err(e) => {
            pam_log!("ERROR", "Session open failed: {}", e);
            12
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: i32,
    _argc: i32,
    _argv: *const *const c_char,
) -> i32 {
    pam_log!("DEBUG", "pam_sm_close_session called");
    0
}

fn handle_session_open(pamh: *mut PamHandle) -> Result<()> {
    let username = get_pam_user(pamh)?;
    let uid = get_user_uid(&username)?;
    let cached = load_cached_token(uid)?;
    if cached.is_expired() || cached.username != username {
        return Err(anyhow!("Invalid session token"));
    }
    Ok(())
}

fn get_pam_user(pamh: *mut PamHandle) -> Result<String> {
    unsafe {
        let mut ptr: *const c_char = std::ptr::null();
        let r = pam_sys::raw::pam_get_item(pamh, PAM_USER, &mut ptr as *mut _ as *mut *const c_void);
        if r != 0 || ptr.is_null() {
            return Err(anyhow!("Failed to get PAM_USER, code: {}", r));
        }
        let cstr = CStr::from_ptr(ptr);
        let username = cstr.to_string_lossy().into_owned();
        pam_log!("DEBUG", "Retrieved PAM_USER: {}", username);
        Ok(username)
    }
}

fn get_pam_authtok(pamh: *mut PamHandle) -> Result<String> {
    unsafe {
        let mut ptr: *const c_char = std::ptr::null();
        let r = pam_sys::raw::pam_get_item(pamh, PAM_AUTHTOK, &mut ptr as *mut _ as *mut *const c_void);
        
        if r != 0 || ptr.is_null() {
            return Err(anyhow!("PAM_AUTHTOK unavailable, code: {}", r));
        }
        
        let cstr = match CStr::from_ptr(ptr).to_str() {
            Ok(s) => s,
            Err(_) => return Err(anyhow!("PAM_AUTHTOK invalid UTF-8")),
        };
        
        if cstr.is_empty() || cstr.len() > 1024 {
            return Err(anyhow!("PAM_AUTHTOK invalid length: {}", cstr.len()));
        }
        
        let has_reasonable_chars = cstr.chars().all(|c| c.is_ascii() && (c.is_alphanumeric() || c.is_ascii_punctuation() || c == ' '));
        if !has_reasonable_chars {
            return Err(anyhow!("PAM_AUTHTOK contains invalid characters"));
        }
        
        pam_log!("DEBUG", "Retrieved PAM_AUTHTOK (length: {})", cstr.len());
        Ok(cstr.to_string())
    }
}

fn get_pam_password_with_fallback(pamh: *mut PamHandle) -> Result<String> {
    // Try PAM_AUTHTOK first
    if let Ok(password) = get_pam_authtok(pamh) {
        return Ok(password);
    }
    
    // Fallback to PAM_OLDAUTHTOK
    unsafe {
        let mut ptr: *const c_char = std::ptr::null();
        let r = pam_sys::raw::pam_get_item(pamh, PAM_OLDAUTHTOK, &mut ptr as *mut _ as *mut *const c_void);
        
        if r == 0 && !ptr.is_null() {
            if let Ok(cstr) = CStr::from_ptr(ptr).to_str() {
                if !cstr.is_empty() && cstr.len() < 1024 {
                    pam_log!("DEBUG", "Retrieved PAM_OLDAUTHTOK (length: {})", cstr.len());
                    return Ok(cstr.to_string());
                }
            }
        }
    }
    
    Err(anyhow!("No password available in PAM tokens"))
}

fn get_password_via_conversation(pamh: *mut PamHandle) -> Result<String> {
    pam_log!("DEBUG", "Attempting to get password via PAM conversation");
    unsafe {
        let mut conv_ptr: *const c_void = std::ptr::null();
        let result = pam_sys::raw::pam_get_item(pamh, PAM_CONV, &mut conv_ptr as *mut *const c_void);
        if result != 0 || conv_ptr.is_null() {
            return Err(anyhow!("PAM_CONV unavailable, code: {}", result));
        }
        
        let conv = &*(conv_ptr as *const PamConv);
        let prompt = CString::new("SuperNanny Password: ").unwrap();
        let msg = PamMessage { 
            msg_style: PAM_PROMPT_ECHO_OFF, 
            msg: prompt.as_ptr() 
        };
        let msg_ptr = &msg as *const PamMessage;
        let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();
        
        let result = (conv.conv)(
            1, 
            &msg_ptr as *const _ as *mut *const PamMessage, 
            &mut resp_ptr, 
            conv.appdata_ptr
        );
        
        if result != 0 || resp_ptr.is_null() {
            return Err(anyhow!("Conversation failed, code: {}", result));
        }
        
        let resp = &*resp_ptr;
        if resp.resp.is_null() {
            libc::free(resp_ptr as *mut c_void);
            return Err(anyhow!("Empty password response"));
        }
        
        let password_bytes = CStr::from_ptr(resp.resp).to_bytes();
        let password = match std::str::from_utf8(password_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => password_bytes.iter().map(|&b| b as char).collect()
        };
        
        libc::free(resp.resp as *mut c_void);
        libc::free(resp_ptr as *mut c_void);
        
        if password.is_empty() {
            return Err(anyhow!("Empty password"));
        }
        
        pam_log!("DEBUG", "Password obtained via conversation (length: {})", password.len());
        Ok(password)
    }
}

fn get_user_uid(username: &str) -> Result<u32> {
    let out = std::process::Command::new("id").arg("-u").arg(username).output()?;
    if !out.status.success() {
        return Err(anyhow!("Failed to get UID for user: {}", username));
    }
    let s = String::from_utf8(out.stdout)?;
    let uid = s.trim().parse()?;
    pam_log!("DEBUG", "User {} has UID: {}", username, uid);
    Ok(uid)
}

fn authenticate_with_server(username: &str, password: &str) -> Result<CachedToken> {
    let url = std::env::var("SUPERNANNY_SERVER_URL").unwrap_or_else(|_| "https://127.0.0.1:8443".into());
    pam_log!("DEBUG", "Authenticating with server: {}", url);
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let payload = serde_json::json!({ "username": username, "password": password });
    
    let resp = match client.post(&format!("{}/auth/login", url)).json(&payload).send() {
        Ok(resp) => resp,
        Err(e) => {
            pam_log!("ERROR", "Failed to connect to server {}: {}", url, e);
            return Err(anyhow!("Server connection failed: {}", e));
        }
    };
    
    pam_log!("DEBUG", "Server response status: {}", resp.status());
    
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
        pam_log!("ERROR", "Authentication failed: {} - {}", status, body);
        return Err(anyhow!("Authentication failed: {} - {}", status, body));
    }
    
    let lr: LoginResponse = resp.json()?;
    pam_log!("INFO", "Server authentication successful");
    Ok(CachedToken::new(lr.token, username.to_string(), lr.refresh_token))
}

fn refresh_auth_token(rt: &str, username: &str) -> Result<CachedToken> {
    let url = std::env::var("SUPERNANNY_SERVER_URL").unwrap_or_else(|_| "https://127.0.0.1:8443".into());
    pam_log!("DEBUG", "Refreshing token with server: {}", url);
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let resp = client.post(&format!("{}/auth/refresh", url))
        .json(&serde_json::json!({ "refresh_token": rt }))
        .send()?;
    
    if !resp.status().is_success() {
        pam_log!("ERROR", "Token refresh failed: {}", resp.status());
        return Err(anyhow!("Token refresh failed"));
    }
    
    let lr: LoginResponse = resp.json()?;
    pam_log!("INFO", "Token refreshed successfully");
    Ok(CachedToken::new(lr.token, username.to_string(), lr.refresh_token))
}

fn get_cache_dir_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{}/{}", uid, TOKEN_CACHE_DIR))
}

fn get_cache_file_path(uid: u32) -> PathBuf {
    get_cache_dir_path(uid).join(TOKEN_CACHE_FILE)
}

fn save_cached_token(uid: u32, token: &CachedToken) -> Result<()> {
    let dir = get_cache_dir_path(uid);
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let file = get_cache_file_path(uid);
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&file)?;
    f.write_all(serde_json::to_string_pretty(token)?.as_bytes())?;
    pam_log!("DEBUG", "Token cached to: {:?}", file);
    Ok(())
}

fn load_cached_token(uid: u32) -> Result<CachedToken> {
    let file = get_cache_file_path(uid);
    let mut f = File::open(&file)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let token: CachedToken = serde_json::from_str(&s)?;
    pam_log!("DEBUG", "Loaded cached token from: {:?}", file);
    Ok(token)
}

fn clean_cached_token(uid: u32) -> Result<()> {
    let file = get_cache_file_path(uid);
    if file.exists() {
        fs::remove_file(&file)?;
        pam_log!("DEBUG", "Cleaned cached token: {:?}", file);
    }
    Ok(())
}

pub fn get_cached_session_token() -> Result<String> {
    let uid = unsafe { libc::getuid() };
    let cached = load_cached_token(uid)?;
    if cached.is_expired() {
        clean_cached_token(uid)?;
        return Err(anyhow!("Session token expired"));
    }
    Ok(cached.token.clone())
}
