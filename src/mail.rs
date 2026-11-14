//! Sends email from the auth service through Resend. Set `RESEND_API_KEY` to turn it on. Without it
//! nothing is sent. `VAXELIUM_MAIL_FROM` sets the sender address; it must be on a domain verified with
//! Resend (the default is Resend's test sender, which only delivers to the account that owns Resend).

use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;

const DEFAULT_FROM: &str = "onboarding@resend.dev";

/// True when a Resend key is set, so email can be sent.
pub fn configured() -> bool {
    std::env::var("RESEND_API_KEY").is_ok_and(|key| !key.trim().is_empty())
}

/// Sends the welcome email in the background. Failures are printed and never stop registration.
/// Must be called from inside the Tokio runtime.
pub fn send_welcome(name: String, email: String) {
    let html = format!(
        "<p>Welcome to Vaxelium, {}!</p><p>Your account is ready. Log in with this email address.</p>",
        escape_html(&name)
    );
    send_in_background(email, "Welcome to Vaxelium".into(), html);
}

/// Emails a confirmation code in the background. Must be called from inside the Tokio runtime.
pub fn send_code(email: String, code: String) {
    let html = format!(
        "<p>Your Vaxelium confirmation code is <strong>{code}</strong>.</p><p>It expires in 15 minutes. If you did not ask for it, you can ignore this email.</p>"
    );
    send_in_background(email, "Your Vaxelium confirmation code".into(), html);
}

fn send_in_background(to: String, subject: String, html: String) {
    let Ok(key) = std::env::var("RESEND_API_KEY") else {
        return;
    };
    if key.trim().is_empty() {
        return;
    }
    let from = std::env::var("VAXELIUM_MAIL_FROM").unwrap_or_else(|_| DEFAULT_FROM.to_string());
    tokio::spawn(async move {
        let recipients = [to.as_str()];
        let options = CreateEmailBaseOptions::new(from.as_str(), recipients, subject.as_str()).with_html(&html);
        let resend = Resend::new(&key);
        if let Err(e) = resend.emails.send(options).await {
            eprintln!("could not send an email: {e}");
        }
    });
}

/// Escapes text for use inside HTML.
fn escape_html(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            c => c.to_string(),
        })
        .collect()
}
