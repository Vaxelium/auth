//! The auth service owns every account. Chat servers ask it who a session token
//! belongs to, so one account works on every server.
//!
//! Usage: `auth [ADDR] [DB_PATH]`

mod db;
mod discord;
mod mail;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use common::{is_valid_email, AuthReply, AuthRequest, DEFAULT_AUTH_ADDR};
use db::{username_from, Db};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

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
    let pending: PendingLogins = Arc::default();
    if let Some(config) = discord::config() {
        let pending = pending.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_discord_callbacks(config.callback_addr, pending).await {
                eprintln!("Discord callbacks stopped: {e}");
            }
        });
    }
    let listener = TcpListener::bind(&addr).await?;
    println!("Vaxelium auth service listening on {addr} (TLS), storing accounts in {db_path}");

    loop {
        let (socket, peer) = listener.accept().await?;
        let db = db.clone();
        let pending = pending.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let socket = match acceptor.accept(socket).await {
                Ok(socket) => socket,
                Err(e) => {
                    eprintln!("{peer}: TLS handshake failed: {e}");
                    return;
                }
            };
            if let Err(e) = handle_connection(socket, db, pending).await {
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
async fn handle_connection<S>(socket: S, db: SharedDb, pending: PendingLogins) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(socket);
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let reply = match serde_json::from_str::<AuthRequest>(&line) {
            // Talks to Discord over the network, so it runs here rather than in `handle_request`.
            Ok(AuthRequest::DiscordPoll { state }) => discord_poll(&db, &pending, &state).await,
            Ok(request) => handle_request(&db, &pending, request),
            Err(e) => AuthReply::Error { text: format!("bad request: {e}") },
        };
        let mut out = serde_json::to_string(&reply)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

fn handle_request(db: &SharedDb, pending: &PendingLogins, request: AuthRequest) -> AuthReply {
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
        AuthRequest::SetStatusText { token, text } => {
            return set_status_text(db, &token, text);
        }
        AuthRequest::SetServers { token, servers } => {
            return set_servers(db, &token, servers);
        }
        AuthRequest::SetAvatar { token, png_base64 } => {
            return set_avatar(db, &token, png_base64);
        }
        AuthRequest::ProfileCard { id, token } => {
            return profile_card(db, &id, &token);
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
        AuthRequest::DiscordStart { token } => return discord_start(db, pending, &token),
        AuthRequest::SetPassword { token, password } => return set_password(db, &token, &password),
        AuthRequest::DeleteAccount { token, password } => return delete_account(db, &token, &password),
        AuthRequest::LinkedAccounts { token } => return linked_accounts(db, &token),
        AuthRequest::UnlinkDiscord { token } => return unlink_discord(db, &token),
        // Handled in `handle_connection`, because it talks to Discord.
        AuthRequest::DiscordPoll { .. } => Err("the Discord login is handled separately".to_string()),
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

const DISCORD_NOT_SET_UP: &str = "login with Discord is not set up on this server";
/// How long a Discord login may take from start to finish, in seconds.
const DISCORD_WAIT_SECS: u64 = 10 * 60;

/// A Discord login (or link) that has started and not finished yet.
pub struct PendingLogin {
    /// The session of the account that is linking Discord, or None for a login.
    link: Option<String>,
    created: u64,
    /// The code Discord sent, or why it failed. None until the browser comes back.
    outcome: Option<Result<String, String>>,
}

/// Pending Discord logins, by their state.
pub type PendingLogins = Arc<Mutex<HashMap<String, PendingLogin>>>;

/// Forgets logins that have been waiting too long.
fn drop_stale(pending: &mut HashMap<String, PendingLogin>, now: u64) {
    pending.retain(|_, login| now < login.created + DISCORD_WAIT_SECS);
}

/// Starts a Discord login. With a session token, the Discord account will be linked to that account.
fn discord_start(db: &SharedDb, pending: &PendingLogins, token: &str) -> AuthReply {
    let Some(config) = discord::config() else {
        return AuthReply::Error { text: DISCORD_NOT_SET_UP.into() };
    };
    let link = if token.is_empty() {
        None
    } else {
        let guard = db.lock().unwrap();
        let account = match guard.session_account(token) {
            Ok(Some(account)) => account,
            Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
            Err(e) => return AuthReply::Error { text: e.to_string() },
        };
        match guard.linked_discord_label(&account.id) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return AuthReply::Error { text: "this account already has a Discord account linked. Unlink it first.".into() }
            }
            Err(e) => return AuthReply::Error { text: e.to_string() },
        }
        Some(token.to_string())
    };
    // The state is random. It ties the browser's return to this login.
    let state = new_token();
    let url = match discord::authorize_url(&config, &state) {
        Ok(url) => url,
        Err(text) => return AuthReply::Error { text },
    };
    let now = now_secs();
    let mut logins = pending.lock().unwrap();
    drop_stale(&mut logins, now);
    logins.insert(state.clone(), PendingLogin { link, created: now, outcome: None });
    AuthReply::DiscordUrl { url, state }
}

/// Checks a Discord login. Once the browser has come back, this finishes it: a login gives a session,
/// and a link adds the Discord account to the account that started it.
async fn discord_poll(db: &SharedDb, pending: &PendingLogins, state: &str) -> AuthReply {
    let finished = {
        let mut logins = pending.lock().unwrap();
        drop_stale(&mut logins, now_secs());
        let Some(done) = logins.get(state).map(|login| login.outcome.is_some()) else {
            return AuthReply::Error { text: "this Discord login has expired, start again".into() };
        };
        if !done {
            return AuthReply::DiscordPending;
        }
        logins.remove(state).expect("checked above")
    };
    let code = match finished.outcome {
        Some(Ok(code)) => code,
        Some(Err(text)) => return AuthReply::Error { text },
        None => return AuthReply::DiscordPending,
    };
    let Some(config) = discord::config() else {
        return AuthReply::Error { text: DISCORD_NOT_SET_UP.into() };
    };
    let user = match discord::fetch_user(&config, &code).await {
        Ok(user) => user,
        Err(text) => return AuthReply::Error { text },
    };
    match finished.link {
        Some(token) => link_discord_account(db, &token, &user),
        None => match finish_discord(db, &user) {
            Ok((token, name)) => AuthReply::Session { token, name },
            Err(text) => AuthReply::Error { text },
        },
    }
}

/// Records the Discord account for the session's account. An account can have one Discord account.
fn link_discord_account(db: &SharedDb, token: &str, user: &discord::DiscordUser) -> AuthReply {
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    let fail = |e: rusqlite::Error| AuthReply::Error { text: e.to_string() };
    let owner = match guard.discord_account(&user.id) {
        Ok(owner) => owner,
        Err(e) => return fail(e),
    };
    if owner.as_deref().is_some_and(|other| other != account.id) {
        return AuthReply::Error { text: "that Discord account is linked to another Vaxelium account".into() };
    }
    let has_link = match guard.linked_discord_label(&account.id) {
        Ok(label) => label.is_some(),
        Err(e) => return fail(e),
    };
    if has_link && owner.as_deref() != Some(account.id.as_str()) {
        return AuthReply::Error { text: "this account already has a Discord account linked. Unlink it first.".into() };
    }
    let label = discord_label(user);
    match guard.link_discord(&user.id, &account.id, &label) {
        Ok(()) => AuthReply::DiscordLinked { discord: label },
        Err(e) => fail(e),
    }
}

/// The name a Discord account is shown with: its display name, or its username.
fn discord_label(user: &discord::DiscordUser) -> String {
    user.global_name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(&user.username).to_string()
}

/// Finds or makes the account for a Discord user. The rules, in order:
/// 1. A Discord account already linked to an account logs in to that account.
/// 2. A Discord email that matches an account links to it, but only when that account has confirmed
///    its email. An unconfirmed account could have been registered by someone else with that address.
/// 3. Otherwise a new account is made, with the Discord name and no password.
fn finish_discord(db: &SharedDb, user: &discord::DiscordUser) -> Result<(String, String), String> {
    let email = match (&user.email, user.verified) {
        (Some(email), Some(true)) => normalize_email(email),
        _ => return Err("your Discord email address has to be confirmed to log in with Discord".into()),
    };
    let label = discord_label(user);
    let guard = db.lock().unwrap();
    let token = new_token();
    let now = now_secs();
    let map = |e: rusqlite::Error| e.to_string();

    if let Some(id) = guard.discord_account(&user.id).map_err(map)? {
        if let Some(name) = guard.name_of_account(&id).map_err(map)? {
            // The Discord name may have changed since the link was made, so it is refreshed.
            guard.link_discord(&user.id, &id, &label).map_err(map)?;
            guard.create_session_for_account(&token, &id, now).map_err(map)?;
            return Ok((token, name));
        }
        // The linked account was removed, so the link is made again below.
    }
    if let Some((id, name, verified)) = guard.account_by_email(&email).map_err(map)? {
        if !verified {
            return Err("an account with this email exists but its email is not confirmed. Log in with its password and confirm the email, then try Discord again".into());
        }
        guard.link_discord(&user.id, &id, &label).map_err(map)?;
        guard.create_session_for_account(&token, &id, now).map_err(map)?;
        return Ok((token, name));
    }

    let name = free_name(&guard, &label).map_err(map)?;
    let base = db::username_from(&name);
    let mut username = base.clone();
    let mut n = 2;
    while guard.username_taken(&username).map_err(map)? {
        username = format!("{base}{n}");
        n += 1;
    }
    let id = guard
        .create_discord_account(&name, &username, &email, now)
        .map_err(map)?
        .ok_or_else(|| "that name or email is already registered".to_string())?;
    guard.link_discord(&user.id, &id, &label).map_err(map)?;
    guard.create_session_for_account(&token, &id, now).map_err(map)?;
    drop(guard);
    mail::send_welcome(name.clone(), email);
    Ok((token, name))
}

/// The name, trimmed and cut to the longest allowed. If another account has it, a number is added.
fn free_name(guard: &db::Db, base: &str) -> rusqlite::Result<String> {
    let base: String = base.chars().take(MAX_NAME_LEN).collect();
    let base = if base.trim().is_empty() { "discord user".to_string() } else { base };
    let mut name = base.clone();
    let mut n = 2;
    while guard.account_by_name(&name)?.is_some() {
        let stem: String = base.chars().take(MAX_NAME_LEN - 4).collect();
        name = format!("{stem} {n}");
        n += 1;
    }
    Ok(name)
}

/// Serves the Discord redirect. It only stores what Discord sent, for the poll to pick up.
async fn serve_discord_callbacks(addr: String, pending: PendingLogins) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    println!("Discord callbacks on {addr}{}", discord::CALLBACK_PATH);
    loop {
        let (socket, _) = listener.accept().await?;
        let pending = pending.clone();
        tokio::spawn(async move {
            if let Err(e) = answer_discord_callback(socket, &pending).await {
                eprintln!("Discord callback: {e}");
            }
        });
    }
}

/// Answers one request to the callback with a short page, and keeps what Discord sent.
async fn answer_discord_callback(socket: TcpStream, pending: &PendingLogins) -> std::io::Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut line = String::new();
    BufReader::new(reader).read_line(&mut line).await?;
    let (status, page) = match discord::parse_callback(&line) {
        discord::Callback::Other => ("404 Not Found", callback_page(false, "Page not found", "There is nothing here.")),
        discord::Callback::Broken => (
            "400 Bad Request",
            callback_page(false, "This link is incomplete", "Start the login again in Vaxelium."),
        ),
        discord::Callback::Code { state, code } => {
            if store_outcome(pending, &state, Ok(code)) {
                ("200 OK", callback_page(true, "You are logged in", "You can close this tab and return to Vaxelium."))
            } else {
                ("200 OK", callback_page(false, "This login has expired", "Start it again in Vaxelium."))
            }
        }
        discord::Callback::Failed { state, text } => {
            store_outcome(pending, &state, Err(text));
            (
                "200 OK",
                callback_page(false, "The Discord login did not finish", "You can close this tab and try again in Vaxelium."),
            )
        }
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    writer.write_all(response.as_bytes()).await?;
    writer.shutdown().await
}

/// The page shown in the browser after Discord comes back. The text is fixed, so it needs no escaping.
fn callback_page(ok: bool, heading: &str, message: &str) -> String {
    let (icon, colour) = if ok { ("&#10003;", "#23a55a") } else { ("&#10005;", "#f23f43") };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vaxelium · {heading}</title>
<style>
  /* Dark, to match the app's default theme. */
  :root {{ --bg: #1e1f22; --card: #2b2d31; --text: #f2f3f5; --muted: #b5bac1; --border: #3f4147; }}
  body {{ margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
          padding: 16px; box-sizing: border-box; background: var(--bg); color: var(--text);
          font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
  .card {{ width: 100%; max-width: 380px; background: var(--card); border: 1px solid var(--border);
           border-radius: 12px; padding: 32px 28px; text-align: center; box-sizing: border-box; }}
  .brand {{ font-weight: 700; font-size: 15px; letter-spacing: .04em; color: var(--muted); margin-bottom: 20px; }}
  .icon {{ width: 56px; height: 56px; margin: 0 auto 18px; border-radius: 50%; background: {colour};
           color: #ffffff; font-size: 28px; line-height: 56px; font-weight: 700; }}
  h1 {{ font-size: 22px; margin: 0 0 8px; }}
  p {{ margin: 0; font-size: 15px; line-height: 1.5; color: var(--muted); }}
</style>
</head>
<body>
  <main class="card">
    <div class="brand">VAXELIUM</div>
    <div class="icon" aria-hidden="true">{icon}</div>
    <h1>{heading}</h1>
    <p>{message}</p>
  </main>
</body>
</html>"#
    )
}

/// Records what Discord sent for a login that is waiting. False when no such login is waiting.
fn store_outcome(pending: &PendingLogins, state: &str, outcome: Result<String, String>) -> bool {
    let mut logins = pending.lock().unwrap();
    match logins.get_mut(state) {
        Some(login) if login.outcome.is_none() => {
            login.outcome = Some(outcome);
            true
        }
        _ => false,
    }
}

/// Sets a password on an account that has none, such as one made with Discord.
fn set_password(db: &SharedDb, token: &str, password: &str) -> AuthReply {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return AuthReply::Error { text: format!("password must be at least {MIN_PASSWORD_LEN} characters") };
    }
    if len > MAX_PASSWORD_LEN {
        return AuthReply::Error { text: format!("password must be at most {MAX_PASSWORD_LEN} characters") };
    }
    let account = match db.lock().unwrap().session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    if !account.password_hash.is_empty() {
        return AuthReply::Error { text: "this account already has a password".into() };
    }
    // Hashing is slow, so it is done without holding the database lock.
    let hash = match hash_password(password) {
        Ok(hash) => hash,
        Err(text) => return AuthReply::Error { text },
    };
    match db.lock().unwrap().set_password_hash(&account.email_hash, &hash) {
        Ok(()) => AuthReply::PasswordSet,
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// Deletes the session's account, after checking the password. Accounts without a password cannot be
/// deleted until they set one, because the password is what makes sure it is the owner.
fn delete_account(db: &SharedDb, token: &str, password: &str) -> AuthReply {
    let account = match db.lock().unwrap().session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    if account.password_hash.is_empty() {
        return AuthReply::Error { text: "set a password before you delete your account".into() };
    }
    if !verify_password(password, &account.password_hash) {
        return AuthReply::Error { text: "wrong password".into() };
    }
    let mut guard = db.lock().unwrap();
    match guard.delete_account(&account.email_hash) {
        Ok(()) => AuthReply::AccountDeleted,
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// The Discord account linked to the session's account, and whether the link can be removed.
fn linked_accounts(db: &SharedDb, token: &str) -> AuthReply {
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    match guard.linked_discord_label(&account.id) {
        Ok(label) => AuthReply::LinkedAccounts {
            // Links made before names were stored have an empty label.
            discord: label.map(|name| if name.is_empty() { "a Discord account".to_string() } else { name }),
            // An account made by Discord has no password. Unlinking would leave it with no way to log in.
            can_unlink_discord: !account.password_hash.is_empty(),
        },
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// Removes the Discord link of the session's account, if it has a password to log in with.
fn unlink_discord(db: &SharedDb, token: &str) -> AuthReply {
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    if account.password_hash.is_empty() {
        return AuthReply::Error {
            text: "this account signs in with Discord only. Set a password first, then unlink Discord.".into(),
        };
    }
    match guard.unlink_discord(&account.id) {
        Ok(()) => AuthReply::DiscordUnlinked,
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
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
                has_password: !account.password_hash.is_empty(),
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
        has_password: !account.password_hash.is_empty(),
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

/// Sets the status text shown on the account's profile card. Empty clears it.
/// The most servers an account can report, and the longest address.
const MAX_SERVERS: usize = 500;
const MAX_SERVER_ADDR_LEN: usize = 255;

/// Saves the servers this account is in. Addresses are kept one per line.
fn set_servers(db: &SharedDb, token: &str, servers: Vec<String>) -> AuthReply {
    let mut clean: Vec<String> = servers
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= MAX_SERVER_ADDR_LEN && !s.contains('\n'))
        .collect();
    clean.dedup();
    clean.truncate(MAX_SERVERS);
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    match guard.set_servers(&account.email_hash, &clean.join("\n")) {
        Ok(()) => AuthReply::ServersSaved,
        Err(e) => AuthReply::Error { text: e.to_string() },
    }
}

/// The profile card of an account. With the viewer's session, it lists the servers they share.
fn profile_card(db: &SharedDb, id: &str, token: &str) -> AuthReply {
    let guard = db.lock().unwrap();
    let card = match guard.profile_card(id) {
        Ok(Some(card)) => card,
        Ok(None) => return AuthReply::Error { text: "there is no such account".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    let (name, username, bio, banner, avatar, created, status) = card;
    let mutual = if token.is_empty() {
        Vec::new()
    } else {
        let viewer = guard.session_account(token).ok().flatten();
        match (viewer, guard.servers_for_id(id)) {
            (Some(viewer), Ok(theirs)) => {
                let viewer_servers = guard.servers_for_email(&viewer.email_hash).unwrap_or_default();
                // The viewer's order, kept, for the servers both lists have.
                let theirs: Vec<&str> = theirs.lines().collect();
                viewer_servers.lines().filter(|s| theirs.contains(s)).map(String::from).collect()
            }
            _ => Vec::new(),
        }
    };
    AuthReply::ProfileCard { name, username, bio, banner, avatar, created, status, mutual }
}

fn set_status_text(db: &SharedDb, token: &str, text: String) -> AuthReply {
    let text = text.trim().to_string();
    if text.chars().count() > common::MAX_STATUS_TEXT_LEN {
        return AuthReply::Error { text: format!("the status can be at most {} characters", common::MAX_STATUS_TEXT_LEN) };
    }
    let guard = db.lock().unwrap();
    let account = match guard.session_account(token) {
        Ok(Some(account)) => account,
        Ok(None) => return AuthReply::Error { text: "your session has expired, log in again".into() },
        Err(e) => return AuthReply::Error { text: e.to_string() },
    };
    match guard.set_status_text(&account.email_hash, &text) {
        Ok(()) => AuthReply::StatusTextSaved { text },
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

#[cfg(test)]
mod discord_tests {
    use super::*;
    use discord::DiscordUser;

    const KEY: [u8; 32] = [3; 32];

    fn shared() -> SharedDb {
        Arc::new(Mutex::new(Db::open(":memory:", KEY).unwrap()))
    }

    fn discord_user(id: &str, name: &str, email: Option<&str>, verified: Option<bool>) -> DiscordUser {
        DiscordUser {
            id: id.into(),
            username: name.to_lowercase(),
            global_name: Some(name.into()),
            email: email.map(String::from),
            verified,
        }
    }

    fn name_of_session(db: &SharedDb, token: &str) -> Option<String> {
        db.lock().unwrap().session_account(token).unwrap().map(|a| a.name)
    }

    #[test]
    fn a_new_discord_user_gets_an_account_that_logs_in_again() {
        let db = shared();
        let (token, name) = finish_discord(&db, &discord_user("111", "Sky", Some("Sky@Example.com"), Some(true))).unwrap();
        assert_eq!(name, "Sky");
        assert_eq!(name_of_session(&db, &token).as_deref(), Some("Sky"));

        // Discord's name has changed since, but the same Discord account finds the same account.
        let (_, again) = finish_discord(&db, &discord_user("111", "Sky Renamed", Some("sky@example.com"), Some(true))).unwrap();
        assert_eq!(again, "Sky");
    }

    #[test]
    fn a_discord_account_has_no_password_so_password_login_cannot_reach_it() {
        let db = shared();
        finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(true))).unwrap();
        assert!(login(&db, "sky@example.com", "any password at all").is_err());
    }

    #[test]
    fn a_discord_email_that_is_not_confirmed_by_discord_is_refused() {
        let db = shared();
        assert!(finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(false))).is_err());
        assert!(finish_discord(&db, &discord_user("111", "Sky", None, Some(true))).is_err());
        assert!(finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), None)).is_err());
    }

    #[test]
    fn a_confirmed_account_with_the_same_email_is_linked() {
        let db = shared();
        {
            let guard = db.lock().unwrap();
            assert!(guard.create_account("Kai", "kai", "kai@example.com", "some-hash", 1).unwrap());
            guard.set_verified(&db::hash_email(&KEY, "kai@example.com"), true).unwrap();
        }
        let (token, name) = finish_discord(&db, &discord_user("222", "Kai on Discord", Some("kai@example.com"), Some(true))).unwrap();
        assert_eq!(name, "Kai", "logs in to the existing account");
        assert_eq!(name_of_session(&db, &token).as_deref(), Some("Kai"));
        // Linked now, so the next Discord login does not need the email again.
        assert!(db.lock().unwrap().discord_account("222").unwrap().is_some());
    }

    #[test]
    fn an_unconfirmed_account_with_the_same_email_is_not_taken_over() {
        let db = shared();
        db.lock().unwrap().create_account("Ivy", "ivy", "ivy@example.com", "some-hash", 1).unwrap();
        let err = finish_discord(&db, &discord_user("333", "Ivy", Some("ivy@example.com"), Some(true))).unwrap_err();
        assert!(err.contains("not confirmed"), "{err}");
        assert!(db.lock().unwrap().discord_account("333").unwrap().is_none(), "no link was made");
    }

    #[test]
    fn a_discord_only_account_cannot_unlink_discord_but_a_password_account_can() {
        let db = shared();
        let (discord_token, _) = finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(true))).unwrap();
        match linked_accounts(&db, &discord_token) {
            AuthReply::LinkedAccounts { discord, can_unlink_discord } => {
                assert_eq!(discord.as_deref(), Some("Sky"));
                assert!(!can_unlink_discord, "a Discord-only account has no password to fall back on");
            }
            other => panic!("unexpected reply {other:?}"),
        }
        assert!(matches!(unlink_discord(&db, &discord_token), AuthReply::Error { .. }));

        let (kai_token, _) = register(&db, "Kai", "kai@example.com", "a password here").unwrap();
        {
            let guard = db.lock().unwrap();
            let id = guard.session_account(&kai_token).unwrap().unwrap().id;
            guard.link_discord("222", &id, "Kai on Discord").unwrap();
        }
        match linked_accounts(&db, &kai_token) {
            AuthReply::LinkedAccounts { discord, can_unlink_discord } => {
                assert_eq!(discord.as_deref(), Some("Kai on Discord"));
                assert!(can_unlink_discord);
            }
            other => panic!("unexpected reply {other:?}"),
        }
        assert!(matches!(unlink_discord(&db, &kai_token), AuthReply::DiscordUnlinked));
        assert!(matches!(
            linked_accounts(&db, &kai_token),
            AuthReply::LinkedAccounts { discord: None, .. }
        ));
    }

    #[test]
    fn a_discord_login_waits_then_reports_what_discord_sent() {
        let db = shared();
        let pending: PendingLogins = Arc::default();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        pending.lock().unwrap().insert("s1".into(), PendingLogin { link: None, created: now_secs(), outcome: None });

        assert!(matches!(runtime.block_on(discord_poll(&db, &pending, "s1")), AuthReply::DiscordPending));
        assert!(matches!(runtime.block_on(discord_poll(&db, &pending, "unknown")), AuthReply::Error { .. }));

        assert!(store_outcome(&pending, "s1", Err("The Discord login was cancelled.".into())));
        assert!(!store_outcome(&pending, "s1", Ok("late".into())), "a login takes one outcome only");
        match runtime.block_on(discord_poll(&db, &pending, "s1")) {
            AuthReply::Error { text } => assert!(text.contains("cancelled")),
            other => panic!("unexpected reply {other:?}"),
        }
        assert!(matches!(runtime.block_on(discord_poll(&db, &pending, "s1")), AuthReply::Error { .. }), "read once, then gone");
    }

    #[test]
    fn a_password_must_be_set_before_an_account_can_be_deleted() {
        let db = shared();
        let (token, _) = finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(true))).unwrap();
        assert!(matches!(delete_account(&db, &token, "anything"), AuthReply::Error { .. }));
        assert!(matches!(set_password(&db, &token, "short"), AuthReply::Error { .. }));
        assert!(matches!(set_password(&db, &token, "a long enough password"), AuthReply::PasswordSet));
        assert!(matches!(set_password(&db, &token, "another password"), AuthReply::Error { .. }), "only once");
        assert!(matches!(delete_account(&db, &token, "wrong password"), AuthReply::Error { .. }));
        assert!(matches!(delete_account(&db, &token, "a long enough password"), AuthReply::AccountDeleted));
        assert!(name_of_session(&db, &token).is_none());
        assert!(login(&db, "sky@example.com", "a long enough password").is_err());
    }

    #[test]
    fn a_taken_display_name_gets_a_number() {
        let db = shared();
        finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(true))).unwrap();
        let (_, name) = finish_discord(&db, &discord_user("444", "Sky", Some("other@example.com"), Some(true))).unwrap();
        assert_eq!(name, "Sky 2");
    }
}
