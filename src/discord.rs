//! Login with Discord. The browser goes to Discord, which sends it back to the client with a code.
//! This module trades that code for the Discord account's details. It needs `DISCORD_CLIENT_ID` and
//! `DISCORD_CLIENT_SECRET`, set in `.env` or the shell.

use serde::Deserialize;

const AUTHORIZE_URL: &str = "https://discord.com/oauth2/authorize";
const TOKEN_URL: &str = "https://discord.com/api/oauth2/token";
const ME_URL: &str = "https://discord.com/api/users/@me";

/// The application's id and secret from the Discord developer portal.
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
}

/// The Discord settings, or `None` when they are not set (Discord login is then off).
pub fn config() -> Option<Config> {
    let client_id = std::env::var("DISCORD_CLIENT_ID").ok()?.trim().to_string();
    let client_secret = std::env::var("DISCORD_CLIENT_SECRET").ok()?.trim().to_string();
    (!client_id.is_empty() && !client_secret.is_empty()).then_some(Config { client_id, client_secret })
}

/// The redirect has to go to this computer. Discord also checks it against the registered URIs.
pub fn check_redirect(uri: &str) -> Result<(), String> {
    if uri.starts_with("http://127.0.0.1:") || uri.starts_with("http://localhost:") {
        Ok(())
    } else {
        Err("the Discord login has to return to this computer".into())
    }
}

/// The Discord page to open. Asks for the account's name and email.
pub fn authorize_url(config: &Config, redirect_uri: &str, state: &str) -> Result<String, String> {
    reqwest::Url::parse_with_params(
        AUTHORIZE_URL,
        &[
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "identify email"),
            ("state", state),
        ],
    )
    .map(|url| url.to_string())
    .map_err(|e| e.to_string())
}

/// The parts of a Discord account that Vaxelium uses.
#[derive(Debug, Deserialize)]
pub struct DiscordUser {
    /// Discord's id for the account. It does not change.
    pub id: String,
    pub username: String,
    pub global_name: Option<String>,
    pub email: Option<String>,
    pub verified: Option<bool>,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
}

/// Trades the code for an access token, then asks Discord who it belongs to.
pub async fn fetch_user(config: &Config, code: &str, redirect_uri: &str) -> Result<DiscordUser, String> {
    let http = reqwest::Client::new();
    let token: TokenReply = http
        .post(TOKEN_URL)
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|e| format!("could not reach Discord: {e}"))?
        .error_for_status()
        .map_err(|_| "Discord did not accept that login. Try again.".to_string())?
        .json()
        .await
        .map_err(|e| format!("bad reply from Discord: {e}"))?;
    http.get(ME_URL)
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| format!("could not reach Discord: {e}"))?
        .error_for_status()
        .map_err(|_| "Discord did not share the account details. Try again.".to_string())?
        .json()
        .await
        .map_err(|e| format!("bad reply from Discord: {e}"))
}
