use super::*;

#[test]
fn a_callback_gives_its_state_and_code() {
    assert_eq!(
        parse_callback("GET /discord/callback?code=abc&state=s1 HTTP/1.1"),
        Callback::Code {
            state: "s1".into(),
            code: "abc".into()
        }
    );
    assert_eq!(
        parse_callback("GET /discord/callback?state=s1&code=abc HTTP/1.1"),
        Callback::Code {
            state: "s1".into(),
            code: "abc".into()
        }
    );
}

#[test]
fn a_cancelled_login_is_reported_for_its_state() {
    assert!(matches!(
        parse_callback("GET /discord/callback?error=access_denied&state=s1 HTTP/1.1"),
        Callback::Failed { state, .. } if state == "s1"
    ));
}

#[test]
fn other_requests_are_not_callbacks() {
    assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1"), Callback::Other);
    assert_eq!(
        parse_callback("GET /discord/callbackx?code=a&state=b HTTP/1.1"),
        Callback::Other
    );
    assert_eq!(
        parse_callback("POST /discord/callback?code=a&state=b HTTP/1.1"),
        Callback::Other
    );
}

#[test]
fn a_callback_without_a_state_is_broken() {
    assert_eq!(
        parse_callback("GET /discord/callback?code=abc HTTP/1.1"),
        Callback::Broken
    );
}
