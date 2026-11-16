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
    let (_, again) = finish_discord(
        &db,
        &discord_user("111", "Sky Renamed", Some("sky@example.com"), Some(true)),
    )
    .unwrap();
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
        assert!(guard
            .create_account("Kai", "kai", "kai@example.com", "some-hash", 1)
            .unwrap());
        guard
            .set_verified(&db::hash_email(&KEY, "kai@example.com"), true)
            .unwrap();
    }
    let (token, name) = finish_discord(
        &db,
        &discord_user("222", "Kai on Discord", Some("kai@example.com"), Some(true)),
    )
    .unwrap();
    assert_eq!(name, "Kai", "logs in to the existing account");
    assert_eq!(name_of_session(&db, &token).as_deref(), Some("Kai"));
    // Linked now, so the next Discord login does not need the email again.
    assert!(db.lock().unwrap().discord_account("222").unwrap().is_some());
}

#[test]
fn an_unconfirmed_account_with_the_same_email_is_not_taken_over() {
    let db = shared();
    db.lock()
        .unwrap()
        .create_account("Ivy", "ivy", "ivy@example.com", "some-hash", 1)
        .unwrap();
    let err = finish_discord(&db, &discord_user("333", "Ivy", Some("ivy@example.com"), Some(true))).unwrap_err();
    assert!(err.contains("not confirmed"), "{err}");
    assert!(
        db.lock().unwrap().discord_account("333").unwrap().is_none(),
        "no link was made"
    );
}

#[test]
fn a_discord_only_account_cannot_unlink_discord_but_a_password_account_can() {
    let db = shared();
    let (discord_token, _) =
        finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(true))).unwrap();
    match linked_accounts(&db, &discord_token) {
        AuthReply::LinkedAccounts {
            discord,
            can_unlink_discord,
        } => {
            assert_eq!(discord.as_deref(), Some("Sky"));
            assert!(
                !can_unlink_discord,
                "a Discord-only account has no password to fall back on"
            );
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
        AuthReply::LinkedAccounts {
            discord,
            can_unlink_discord,
        } => {
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
    pending.lock().unwrap().insert(
        "s1".into(),
        PendingLogin {
            link: None,
            created: now_secs(),
            outcome: None,
        },
    );

    assert!(matches!(
        runtime.block_on(discord_poll(&db, &pending, "s1")),
        AuthReply::DiscordPending
    ));
    assert!(matches!(
        runtime.block_on(discord_poll(&db, &pending, "unknown")),
        AuthReply::Error { .. }
    ));

    assert!(store_outcome(
        &pending,
        "s1",
        Err("The Discord login was cancelled.".into())
    ));
    assert!(
        !store_outcome(&pending, "s1", Ok("late".into())),
        "a login takes one outcome only"
    );
    match runtime.block_on(discord_poll(&db, &pending, "s1")) {
        AuthReply::Error { text } => assert!(text.contains("cancelled")),
        other => panic!("unexpected reply {other:?}"),
    }
    assert!(
        matches!(
            runtime.block_on(discord_poll(&db, &pending, "s1")),
            AuthReply::Error { .. }
        ),
        "read once, then gone"
    );
}

#[test]
fn a_password_must_be_set_before_an_account_can_be_deleted() {
    let db = shared();
    let (token, _) = finish_discord(&db, &discord_user("111", "Sky", Some("sky@example.com"), Some(true))).unwrap();
    assert!(matches!(
        delete_account(&db, &token, "anything"),
        AuthReply::Error { .. }
    ));
    assert!(matches!(set_password(&db, &token, "short"), AuthReply::Error { .. }));
    assert!(matches!(
        set_password(&db, &token, "a long enough password"),
        AuthReply::PasswordSet
    ));
    assert!(
        matches!(set_password(&db, &token, "another password"), AuthReply::Error { .. }),
        "only once"
    );
    assert!(matches!(
        delete_account(&db, &token, "wrong password"),
        AuthReply::Error { .. }
    ));
    assert!(matches!(
        delete_account(&db, &token, "a long enough password"),
        AuthReply::AccountDeleted
    ));
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
