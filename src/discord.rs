//! Login with Discord. The browser goes to Discord, which sends it to the auth service's callback
//! address (behind a domain, if the server has one) with a code. The service trades that code for the
//! Discord account's details. The client waits for the result by polling the service, so it does not
//! need to be reachable from the internet.
//!
//! Settings, in `.env` or the shell:
//! - `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET`: from the Discord developer portal.
//! - `DISCORD_REDIRECT_URI`: the URL Discord sends the browser to, e.g.
//!   `https://login.example.com/discord/callback`. Register the same URL in the portal.
//! - `DISCORD_CALLBACK_ADDR`: the address this service listens on for that URL, e.g. `127.0.0.1:8080`.
//!   Put nginx (or similar) in front of it when the redirect is on a domain.

use serde::Deserialize;

const AUTHORIZE_URL: &str = "https://discord.com/oauth2/authorize";
const TOKEN_URL: &str = "https://discord.com/api/oauth2/token";
const ME_URL: &str = "https://discord.com/api/users/@me";
/// The path the callback is served on. The redirect URI must end with it.
pub const CALLBACK_PATH: &str = "/discord/callback";

/// The application's id and secret from the Discord developer portal.
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// The address the callback listener binds to.
    pub callback_addr: String,
}

fn setting(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The Discord settings, or `None` when any of them is missing (Discord login is then off).
pub fn config() -> Option<Config> {
    Some(Config {
        client_id: setting("DISCORD_CLIENT_ID")?,
        client_secret: setting("DISCORD_CLIENT_SECRET")?,
        redirect_uri: setting("DISCORD_REDIRECT_URI")?,
        callback_addr: setting("DISCORD_CALLBACK_ADDR")?,
    })
}

/// The Discord page to open. Asks for the account's name and email.
pub fn authorize_url(config: &Config, state: &str) -> Result<String, String> {
    reqwest::Url::parse_with_params(
        AUTHORIZE_URL,
        &[
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
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
pub async fn fetch_user(config: &Config, code: &str) -> Result<DiscordUser, String> {
    let http = reqwest::Client::new();
    let token: TokenReply = http
        .post(TOKEN_URL)
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
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

/// What a request to the callback means.
#[derive(Debug, PartialEq)]
pub enum Callback {
    /// Not the callback path. Answer 404.
    Other,
    /// Discord sent a code for the login with this state.
    Code { state: String, code: String },
    /// Discord reported a problem (for example the login was cancelled) for this state.
    Failed { state: String, text: String },
    /// The callback arrived without the state or code it needs.
    Broken,
}

/// Reads a request line such as `GET /discord/callback?code=abc&state=xyz HTTP/1.1`.
pub fn parse_callback(request_line: &str) -> Callback {
    let mut parts = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Callback::Other;
    };
    let Some(query) = target.strip_prefix(CALLBACK_PATH).and_then(|rest| {
        if rest.is_empty() {
            Some("")
        } else {
            rest.strip_prefix('?')
        }
    }) else {
        return Callback::Other;
    };
    let mut code = None;
    let mut state = None;
    let mut error = false;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            "error" => error = true,
            _ => {}
        }
    }
    let Some(state) = state.filter(|s| !s.is_empty()) else {
        return Callback::Broken;
    };
    if error {
        return Callback::Failed {
            state,
            text: "The Discord login was cancelled.".into(),
        };
    }
    match code.filter(|c| !c.is_empty()) {
        Some(code) => Callback::Code { state, code },
        None => Callback::Failed {
            state,
            text: "Discord did not send a login code. Try again.".into(),
        },
    }
}

#[cfg(test)]
#[path = "tests/discord.rs"]
mod tests;
