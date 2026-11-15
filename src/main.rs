//! The auth service owns every account. Chat servers ask it who a session token
//! belongs to, so one account works on every server.
//!
//! Usage: `auth [ADDR] [DB_PATH]`

mod db;
mod mail;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use common::{is_valid_email, AuthReply, AuthRequest, DEFAULT_AUTH_ADDR};
use db::{username_from, Db};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const DEFAULT_DB_PATH: &str = "auth.db";
const MAX_NAME_LEN: usize = 24;
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 128;

type SharedDb = Arc<Mutex<Db>>;

fn main() -> anyhow::Result<()> {
    // Read .env before the runtime starts any threads (RESEND_API_KEY and other settings live there).
    common::env::load();
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| DEFAULT_AUTH_ADDR.to_string());
    let db_path = args.next().unwrap_or_else(|| DEFAULT_DB_PATH.to_string());

    let key = load_email_key(&db_path)?;
    let mut db = Db::open(&db_path, key)?;
    let converted = db.hash_plain_emails()?;
    if converted > 0 {
        println!("hashed {converted} stored email address(es)");
    }
    // The service's own certificate. It is made the first time the service runs.
    let (cert, key) = match db.tls_identity()? {
        Some(identity) => identity,
        None => {
            let identity = common::tls::new_identity()?;
            db.store_tls_identity(&identity.0, &identity.1)?;
            identity
        }
    };
    let acceptor = common::tls::acceptor(&cert, &key)?;
    let db: SharedDb = Arc::new(Mutex::new(db));
    let listener = TcpListener::bind(&addr).await?;
    println!("Vaxelium auth service listening on {addr} (TLS), storing accounts in {db_path}");

    loop {
        let (socket, peer) = listener.accept().await?;
        let db = db.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let socket = match acceptor.accept(socket).await {
                Ok(socket) => socket,
                Err(e) => {
                    eprintln!("{peer}: TLS handshake failed: {e}");
                    return;
                }
            };
            if let Err(e) = handle_connection(socket, db).await {
                if !common::tls::is_quiet_close(&e) {
                    eprintln!("{peer}: {e}");
                }
            }
        });
    }
}

/// The secret used to hash emails. It is kept in `<DB_PATH>.key`, made the first time the
/// service runs. Keep it apart from the database: someone with only the database cannot read
/// the emails.
fn load_email_key(db_path: &str) -> anyhow::Result<[u8; 32]> {
    let path = format!("{db_path}.key");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let bytes = hex_decode(text.trim()).filter(|b| b.len() == 32);
        return bytes
            .map(|b| b.try_into().expect("checked length"))
            .ok_or_else(|| anyhow::anyhow!("{path} does not hold a valid key"));
    }
    // No key file yet. That is only safe when no account has a hashed email, because a new key
    // could not match those.
    if std::path::Path::new(db_path).exists() {
        let existing = Db::open(db_path, [0; 32])?;
        if existing.hashed_account_count()? > 0 {
            anyhow::bail!("{path} is missing, but accounts in {db_path} need it to log in");
        }
    }
    let key: [u8; 32] = rand::random();
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, hex)?;
    println!("made a new email key in {path}");
    Ok(key)
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Reads requests line by line until the client disconnects.
async fn handle_connection<S>(socket: S, db: SharedDb) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(socket);
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let reply = match serde_json::from_str::<AuthRequest>(&line) {
            Ok(request) => handle_request(&db, request),
            Err(e) => AuthReply::Error { text: format!("bad request: {e}") },
        };
        let mut out = serde_json::to_string(&reply)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

fn handle_request(db: &SharedDb, request: AuthRequest) -> AuthReply {
    let result = match request {
        AuthRequest::Register { name, email, password } => register(db, &name, &email, &password),
        AuthRequest::Login { email, password } => login(db, &email, &password),
        AuthRequest::Verify { token } => {
            return match db.lock().unwrap().session_account(&token) {
                Ok(Some(account)) => AuthReply::Verified { id: account.id, name: account.name },
                Ok(None) => AuthReply::Error { text: "your session has expired, log in again".into() },
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
        AuthRequest::Profile { token } => return profile(db, &token),
        AuthRequest::RequestEmailCode { token } => return request_email_code(db, &token),
        AuthRequest::VerifyEmail { token, code } => return verify_email(db, &token, &code),
        AuthRequest::UpdateProfile { token, name, username } => {
            return update_profile(db, &token, name, username);
        }
        AuthRequest::SetAbout { token, bio, banner } => {
            return set_about(db, &token, bio, banner);
        }
        AuthRequest::SetAvatar { token, png_base64 } => {
            return set_avatar(db, &token, png_base64);
        }
        AuthRequest::ProfileCard { id } => {
            return match db.lock().unwrap().profile_card(&id) {
                Ok(Some((name, username, bio, banner, avatar, created))) => AuthReply::ProfileCard { name, username, bio, banner, avatar, created },
                Ok(None) => AuthReply::Error { text: "there is no such account".into() },
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
        AuthRequest::ChangeEmail { token, password, new_email } => {
            return change_email(db, &token, &password, &new_email);
        }
        AuthRequest::Logout { token } => {
            return match db.lock().unwrap().delete_session(&token) {
                Ok(()) => AuthReply::LoggedOut,
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
        AuthRequest::Lookup { name } => {
            return match db.lock().unwrap().account_by_name(&name) {
                Ok(Some((id, name))) => AuthReply::Account { id, name },
                Ok(None) => AuthReply::Error { text: format!("there is no account named {name}") },
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
        AuthRequest::Seen { token, addr } => {
            let db = db.lock().unwrap();
            return match db.session_account(&token) {
                Ok(Some(account)) => match db.record_location(&account.id, &addr, now_secs()) {
                    Ok(()) => AuthReply::Recorded,
                    Err(e) => AuthReply::Error { text: e.to_string() },
                },
                Ok(None) => AuthReply::Error { text: "your session has expired, log in again".into() },
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
        AuthRequest::Migrations { old_ids } => {
            return match db.lock().unwrap().migrations_for(&old_ids) {
                Ok(pairs) => AuthReply::Migrations { pairs },
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
        AuthRequest::Locate { id } => {
            return match db.lock().unwrap().locations_of(&id) {
                Ok(addrs) => AuthReply::Locations { addrs },
                Err(e) => AuthReply::Error { text: e.to_string() },
            };
        }
    };
    match result {
        Ok((token, name)) => AuthReply::Session { token, name },
        Err(text) => AuthReply::Error { text },
    }
}

/// Creates an account and a session. Returns `(token, name)`.
fn register(db: &SharedDb, name: &str, email: &str, password: &str) -> Result<(String, String), String> {
    let name = name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(format!("name must be 1-{MAX_NAME_LEN} characters"));
    }
    let email = normalize_email(email);
    if !is_valid_email(&email) {
        return Err("enter a valid email address".into());
    }
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(format!("password must be at least {MIN_PASSWORD_LEN} characters"));
    }
    if len > MAX_PASSWORD_LEN {
        return Err(format!("password must be at most {MAX_PASSWORD_LEN} characters"));
    }

    let hash = hash_password(password)?;
    let token = new_token();
    let guard = db.lock().unwrap();
    // The username starts as the name in lowercase, with a number added if that is taken.
    let base = username_from(&name);
    let mut username = base.clone();
    let mut n = 2;
    while guard.username_taken(&username).map_err(|e| e.to_string())? {
        username = format!("{base}{n}");
        n += 1;
    }
    let created = guard
        .create_account(&name, &username, &email, &hash, now_secs())
        .map_err(|e| e.to_string())?;
    if !created {
        return Err("that name or email is already registered".into());
    }
    guard
        .create_session(&token, &email, now_secs())
        .map_err(|e| e.to_string())?;
    mail::send_welcome(name.clone(), email);
    Ok((token, name))
}

/// Checks an email and password. Returns `(token, name)`.
fn login(db: &SharedDb, email: &str, password: &str) -> Result<(String, String), String> {
    let email = normalize_email(email);
    // Look the account up, then release the lock before the slow password check.
    let account = db
        .lock()
        .unwrap()
        .find_account(&email)
        .map_err(|e| e.to_string())?;
    let account = match account {
        Some(acc) if verify_password(password, &acc.password_hash) => acc,
        _ => return Err("wrong email or password".into()),
    };

    let token = new_token();
    db.lock()
        .unwrap()
        .create_session(&token, &email, now_secs())
        .map_err(|e| e.to_string())?;
    Ok((token, account.name))
}

/// The account's name and email, for the session's owner.
fn profile(db: &SharedDb, token: &str) -> AuthReply {
    let guard = db.lock().unwrap();
    match guard.session_account(token) {
        Ok(Some(account)) => {
            let (bio, banner) = guard.about(&account.email_hash).unwrap_or_default();
            let avatar = guard.avatar(&account.email_hash).unwrap_or_default();
            AuthReply::Profile {
                name: account.name.clone(),
                username: account.username.clone(),
                email: guard.account_email(&account),
                verified: guard.is_verified(&account.email_hash).unwrap_or(false),
                can_verify: mail::configured(),
                bio,
                banner,
                avatar,
            }
        }
        Ok(None) => AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// Changes the display name and/or the username of the session's account. Usernames are
/// lowercase letters, digits and underscores, 2 to 24 characters.
fn update_profile(db: &SharedDb, token: &str, name: Option<String>, username: Option<String>) -> AuthReply {
    let account = match db.lock().unwrap().session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    let guard = db.lock().unwrap();
    if let Some(name) = name {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
            return AuthReply::Error { text: format!("name must be 1-{MAX_NAME_LEN} characters") };
        }
        match guard.set_display_name(&account.email_hash, &name) {
            Ok(true) => {}
            Ok(false) => return AuthReply::Error { text: "that name is already taken".into() },
            Err(e) => return AuthReply::Error { text: e.to_string() },
        }
    }
    if let Some(username) = username {
        let username = username.trim().to_lowercase();
        let valid = (2..=24).contains(&username.len())
            && username.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid {
            return AuthReply::Error {
                text: "usernames are 2-24 letters, digits or underscores".into(),
            };
        }
        match guard.set_username(&account.email_hash, &username) {
            Ok(true) => {}
            Ok(false) => return AuthReply::Error { text: "that username is taken".into() },
            Err(e) => return AuthReply::Error { text: e.to_string() },
        }
    }
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        _ => return AuthReply::Error { text: "your session has expired, log in again".into() },
    };
    let (bio, banner) = guard.about(&account.email_hash).unwrap_or_default();
    let avatar = guard.avatar(&account.email_hash).unwrap_or_default();
    AuthReply::Profile {
        name: account.name.clone(),
        username: account.username.clone(),
        email: guard.account_email(&account),
        verified: guard.is_verified(&account.email_hash).unwrap_or(false),
        can_verify: mail::configured(),
        bio,
        banner,
        avatar,
    }
}

/// Sets or removes the session's account's profile picture.
fn set_avatar(db: &SharedDb, token: &str, png_base64: Option<String>) -> AuthReply {
    let avatar = png_base64.unwrap_or_default();
    if avatar.len() > common::MAX_AVATAR_LEN {
        return AuthReply::Error { text: "that picture is too large".into() };
    }
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    match guard.set_avatar(&account.email_hash, &avatar) {
        Ok(()) => AuthReply::AvatarSaved { avatar },
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// Sets the bio (at most 190 characters) and the banner colour (`#rrggbb`, or empty for the default).
fn set_about(db: &SharedDb, token: &str, bio: String, banner: String) -> AuthReply {
    let bio = bio.trim().to_string();
    let banner = banner.trim().to_string();
    if bio.chars().count() > 190 {
        return AuthReply::Error { text: "the bio can be at most 190 characters".into() };
    }
    let banner_ok = banner.is_empty() || (banner.len() == 7 && banner.starts_with('#') && banner[1..].bytes().all(|b| b.is_ascii_hexdigit()));
    if !banner_ok {
        return AuthReply::Error { text: "the banner colour must look like #rrggbb".into() };
    }
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    match guard.set_about(&account.email_hash, &bio, &banner) {
        Ok(()) => AuthReply::AboutSaved { bio, banner },
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// Changes the email of the session's account, after checking the current password.
fn change_email(db: &SharedDb, token: &str, password: &str, new_email: &str) -> AuthReply {
    let new_email = normalize_email(new_email);
    if !is_valid_email(&new_email) {
        return AuthReply::Error { text: "enter a valid email address".into() };
    }
    // Read the account, then release the lock before the slow password check.
    let account = match db.lock().unwrap().session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    if !verify_password(password, &account.password_hash) {
        return AuthReply::Error { text: "wrong password".into() };
    }
    let mut guard = db.lock().unwrap();
    match guard.change_email(&account.email_hash, &new_email) {
        Ok(true) => AuthReply::EmailChanged { email: new_email },
        Ok(false) => AuthReply::Error { text: "that email is already registered".into() },
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// How long a confirmation code stays valid, in seconds.
const CODE_SECS: u64 = 15 * 60;
/// Wrong codes allowed before a new one has to be asked for.
const MAX_CODE_TRIES: u32 = 5;
/// Seconds to wait between codes.
const CODE_WAIT_SECS: u64 = 60;

/// The stored form of a code: a hash of the code, tied to the account so the same code gives a
/// different hash for each account.
fn code_hash(email_hash: &str, code: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("{email_hash}:{code}").as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Emails a new six-digit code to the account's address.
fn request_email_code(db: &SharedDb, token: &str) -> AuthReply {
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    if guard.is_verified(&account.email_hash).unwrap_or(false) {
        return AuthReply::Error { text: "your email is already confirmed".into() };
    }
    let Some(email) = guard.account_email(&account) else {
        return AuthReply::Error { text: "this account has no email address on record".into() };
    };
    if !mail::configured() {
        return AuthReply::Error { text: "email sending is not set up on this server".into() };
    }
    let now = now_secs();
    if let Ok(Some((_, _, _, sent))) = guard.pending_code(&account.email_hash) {
        if now < sent + CODE_WAIT_SECS {
            return AuthReply::Error { text: "wait a minute before asking for another code".into() };
        }
    }
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    if let Err(e) = guard.store_code(&account.email_hash, &code_hash(&account.email_hash, &code), now + CODE_SECS, now) {
        return AuthReply::Error { text: e.to_string() };
    }
    drop(guard);
    mail::send_code(email, code);
    AuthReply::CodeSent
}

/// Checks the code that was emailed, and confirms the account's address if it is right.
fn verify_email(db: &SharedDb, token: &str, code: &str) -> AuthReply {
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    let (stored, expires, tries, _) = match guard.pending_code(&account.email_hash) {
        Ok(Some(pending)) => pending,
        Ok(None) => return AuthReply::Error { text: "ask for a code first".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    if now_secs() > expires {
        let _ = guard.clear_code(&account.email_hash);
        return AuthReply::Error { text: "that code has expired, ask for a new one".into() };
    }
    if tries >= MAX_CODE_TRIES {
        return AuthReply::Error { text: "too many wrong codes, ask for a new one".into() };
    }
    if code_hash(&account.email_hash, code.trim()) != stored {
        let _ = guard.count_wrong_code(&account.email_hash);
        return AuthReply::Error { text: "that code is wrong".into() };
    }
    let _ = guard.set_verified(&account.email_hash, true);
    let _ = guard.clear_code(&account.email_hash);
    AuthReply::EmailVerified
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Hashes with Argon2 and a random salt. The result is a self-describing string.
fn hash_password(password: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A random 256-bit session token, hex-encoded.
fn new_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
