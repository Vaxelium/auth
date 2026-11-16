mod id_tests {
    use super::super::*;

    #[test]
    fn an_account_keeps_its_id_when_its_name_or_username_changes() {
        let key = [7u8; 32];
        let db = Db::open(":memory:", key).unwrap();
        let email = "someone@example.com";
        let email_hash = hash_email(&key, email);
        assert!(db.create_account("First", "first", email, "hash", 1).unwrap());
        let (id, name) = db.account_by_name("First").unwrap().expect("created");
        assert_eq!(name, "First");

        assert!(db.set_display_name(&email_hash, "Renamed").unwrap());
        assert!(db.set_username(&email_hash, "renamed_user").unwrap());

        assert!(db.account_by_name("First").unwrap().is_none());
        let (same_id, new_name) = db.account_by_name("Renamed").unwrap().expect("found by new name");
        assert_eq!(same_id, id, "the id did not change");
        assert_eq!(new_name, "Renamed");
    }
}

mod legacy_id_tests {
    use super::super::*;

    #[test]
    fn a_legacy_account_gets_a_random_id_and_the_change_is_recorded() {
        let key = [9u8; 32];
        let db = Db::open(":memory:", key).unwrap();
        assert!(db.create_account("Old", "old", "old@example.com", "hash", 1).unwrap());
        // An account from before random ids: its id is its name.
        db.conn
            .execute("UPDATE accounts SET id = 'Old' WHERE name = 'Old'", [])
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO locations (account, addr, seen) VALUES ('Old', '127.0.0.1:1', 1)",
                [],
            )
            .unwrap();
        let mut db = db;
        assert_eq!(db.migrate_legacy_ids().unwrap(), 1);
        let (new_id, _) = db.account_by_name("Old").unwrap().unwrap();
        assert_ne!(new_id, "Old");
        assert_eq!(new_id.len(), 32, "random ids are 32 hex characters");
        assert_eq!(
            db.locations_of(&new_id).unwrap(),
            vec!["127.0.0.1:1".to_string()],
            "locations follow"
        );
        assert_eq!(
            db.migrations_for(&["Old".to_string()]).unwrap(),
            vec![("Old".to_string(), new_id.clone())],
            "chat servers can ask for the change"
        );
        // Nothing left to migrate the second time.
        assert_eq!(db.migrate_legacy_ids().unwrap(), 0);
    }
}

mod verify_tests {
    use super::super::*;

    #[test]
    fn an_email_is_confirmed_and_a_new_address_must_be_confirmed_again() {
        let key = [9u8; 32];
        let mut db = Db::open(":memory:", key).unwrap();
        let email = "someone@example.com";
        let email_hash = hash_email(&key, email);
        assert!(db.create_account("Someone", "someone", email, "hash", 1).unwrap());
        assert!(!db.is_verified(&email_hash).unwrap(), "new accounts start unconfirmed");

        db.store_code(&email_hash, "code-hash", 1_000, 1).unwrap();
        let (stored, expires, tries, sent) = db.pending_code(&email_hash).unwrap().expect("stored");
        assert_eq!((stored.as_str(), expires, tries, sent), ("code-hash", 1_000, 0, 1));
        db.count_wrong_code(&email_hash).unwrap();
        assert_eq!(db.pending_code(&email_hash).unwrap().unwrap().2, 1);

        db.set_verified(&email_hash, true).unwrap();
        db.clear_code(&email_hash).unwrap();
        assert!(db.is_verified(&email_hash).unwrap());
        assert!(db.pending_code(&email_hash).unwrap().is_none());

        // Changing the address clears the confirmation.
        assert!(db.change_email(&email_hash, "new@example.com").unwrap());
        let new_hash = hash_email(&key, "new@example.com");
        assert!(!db.is_verified(&new_hash).unwrap());
    }
}

mod discord_tests {
    use super::super::*;

    #[test]
    fn a_discord_login_follows_its_account_when_the_email_changes() {
        let key = [4u8; 32];
        let mut db = Db::open(":memory:", key).unwrap();
        let old_email = "before@example.com";
        let id = db
            .create_discord_account("Sky", "sky", old_email, 1)
            .unwrap()
            .expect("created");
        assert!(
            db.is_verified(&hash_email(&key, old_email)).unwrap(),
            "Discord confirmed the email"
        );
        db.link_discord("discord-1", &id, "Sky").unwrap();

        assert!(db
            .change_email(&hash_email(&key, old_email), "after@example.com")
            .unwrap());
        db.create_account_session("token-1", &id, 2).unwrap();
        let account = db.session_account("token-1").unwrap().expect("session");
        assert_eq!(account.id, id);
        assert_eq!(account.email_hash, hash_email(&key, "after@example.com"));
        assert_eq!(
            db.discord_account("discord-1").unwrap(),
            Some(id),
            "the link still holds"
        );
    }
}

mod account_action_tests {
    use super::super::*;

    #[test]
    fn deleting_an_account_removes_everything_it_left_behind() {
        let key = [5u8; 32];
        let mut db = Db::open(":memory:", key).unwrap();
        let email = "gone@example.com";
        let email_hash = hash_email(&key, email);
        let id = db
            .create_discord_account("Gone", "gone", email, 1)
            .unwrap()
            .expect("created");
        db.link_discord("discord-9", &id, "Gone").unwrap();
        db.record_location(&id, "127.0.0.1:7878", 1).unwrap();
        db.create_account_session("token-9", &id, 1).unwrap();
        db.store_code(&email_hash, "code", 99, 1).unwrap();

        db.delete_account(&email_hash).unwrap();

        assert!(db.session_account("token-9").unwrap().is_none());
        assert!(db.discord_account("discord-9").unwrap().is_none());
        assert!(db.locations_of(&id).unwrap().is_empty());
        assert!(db.pending_code(&email_hash).unwrap().is_none());
        assert!(db.account_by_email(email).unwrap().is_none());
    }

    #[test]
    fn a_password_can_be_set_on_a_discord_account() {
        let key = [6u8; 32];
        let db = Db::open(":memory:", key).unwrap();
        let email = "pw@example.com";
        let email_hash = hash_email(&key, email);
        db.create_discord_account("Pat", "pat", email, 1)
            .unwrap()
            .expect("created");
        db.create_account_session("token-pw", &db.account_by_email(email).unwrap().unwrap().0, 1)
            .unwrap();
        assert!(db
            .session_account("token-pw")
            .unwrap()
            .unwrap()
            .password_hash
            .is_empty());

        db.set_password_hash(&email_hash, "new-hash").unwrap();
        assert_eq!(
            db.session_account("token-pw").unwrap().unwrap().password_hash,
            "new-hash"
        );
    }
}
