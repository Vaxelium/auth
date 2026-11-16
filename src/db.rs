//! SQLite storage for accounts and login sessions.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts (
    email         TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created       INTEGER NOT NULL,
    email_enc     TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token   TEXT PRIMARY KEY,
    email   TEXT NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS id_migrations (
    old TEXT PRIMARY KEY,
    new TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_codes (
    email_hash TEXT PRIMARY KEY,
    code_hash  TEXT NOT NULL,
    expires    INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    sent       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS locations (
    account TEXT NOT NULL,
    addr    TEXT NOT NULL,
    seen    INTEGER NOT NULL,
    PRIMARY KEY (account, addr)
);
CREATE TABLE IF NOT EXISTS tls_identity (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    cert TEXT NOT NULL,
    key  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS discord_links (
    discord_id TEXT PRIMARY KEY,
    account    TEXT NOT NULL
);
";

/// The account behind a session token.
pub struct SessionAccount {
    /// The account's hidden id. Chat servers use this to identify people.
    pub id: String,
    /// The stored (hashed) email, which also identifies the account.
    pub email_hash: String,
    /// The name shown in chat.
    pub name: String,
    /// The lowercase handle.
    pub username: String,
    pub password_hash: String,
    pub email_enc: Option<String>,
}

/// A username made from a name: lowercase letters, digits and underscores only.
pub fn username_from(name: &str) -> String {
    let cleaned: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(20)
        .collect();
    if cleaned.len() < 2 {
        format!("user_{cleaned}")
    } else {
        cleaned
    }
}

/// `Ok(true)` when the statement ran, `Ok(false)` when it broke a uniqueness rule.
fn constraint_ok(result: rusqlite::Result<usize>) -> rusqlite::Result<bool> {
    match result {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation => Ok(false),
        Err(e) => Err(e),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A stored account, as needed for logging in.
pub struct Account {
    pub name: String,
    pub password_hash: String,
}

pub struct Db {
    conn: Connection,
    /// Secret that emails are hashed with. It lives in a file beside the database.
    key: [u8; 32],
}

/// Hashes an email (already trimmed and lowercased) with the secret key. The result is what is
/// stored in place of the address, so the database alone does not reveal anyone's email.
pub(crate) fn hash_email(key: &[u8; 32], email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(email.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl Db {
    pub fn open(path: &str, key: [u8; 32]) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        // Databases made before emails could be shown lack this column.
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN email_enc TEXT", []);
        // Accounts made before email confirmation lack this column; they start unconfirmed.
        let _ = conn.execute(
            "ALTER TABLE accounts ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Accounts made before ids and usernames existed. An account's id starts as its name,
        // so the messages it wrote still belong to it. Its username is its name in lowercase.
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN id TEXT", []);
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN username TEXT", []);
        // Profile cards: a short bio and a banner colour. Accounts made before them lack the columns.
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN bio TEXT NOT NULL DEFAULT ''", []);
        let _ = conn.execute(
            "ALTER TABLE accounts ADD COLUMN status_text TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN servers TEXT NOT NULL DEFAULT ''", []);
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN banner TEXT NOT NULL DEFAULT ''", []);
        let _ = conn.execute("ALTER TABLE accounts ADD COLUMN avatar TEXT NOT NULL DEFAULT ''", []);
        // The Discord name shown in the account's settings. Links made before it existed have none.
        let _ = conn.execute(
            "ALTER TABLE discord_links ADD COLUMN label TEXT NOT NULL DEFAULT ''",
            [],
        );
        conn.execute("UPDATE accounts SET id = name WHERE id IS NULL", [])?;
        let mut db = Self { conn, key };
        db.fill_usernames()?;
        db.conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS accounts_id ON accounts (id);
             CREATE UNIQUE INDEX IF NOT EXISTS accounts_username ON accounts (username);",
        )?;
        db.migrate_legacy_ids()?;
        Ok(db)
    }

    /// Gives every account whose id is still its old name a random id, as new accounts get. The
    /// change is recorded, so chat servers can follow it. Accounts already migrated are left alone.
    fn migrate_legacy_ids(&mut self) -> rusqlite::Result<usize> {
        let legacy: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM accounts WHERE length(id) != 32 OR id GLOB '*[^0-9a-f]*'")?;
            let ids = stmt.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            ids
        };
        let tx = self.conn.transaction()?;
        for old in &legacy {
            let new = hex(&rand::random::<[u8; 16]>());
            tx.execute("UPDATE accounts SET id = ?2 WHERE id = ?1", params![old, new])?;
            tx.execute(
                "UPDATE locations SET account = ?2 WHERE account = ?1",
                params![old, new],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO id_migrations (old, new) VALUES (?1, ?2)",
                params![old, new],
            )?;
        }
        tx.commit()?;
        if !legacy.is_empty() {
            println!("gave {} account(s) random ids", legacy.len());
        }
        Ok(legacy.len())
    }

    /// The new ids of the given old ids that were migrated.
    pub fn migrations_for(&self, old_ids: &[String]) -> rusqlite::Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for old in old_ids {
            use rusqlite::OptionalExtension;
            if let Some(new) = self
                .conn
                .query_row("SELECT new FROM id_migrations WHERE old = ?1", params![old], |row| {
                    row.get::<_, String>(0)
                })
                .optional()?
            {
                out.push((old.clone(), new));
            }
        }
        Ok(out)
    }

    /// Gives every account without a username one, from its name. If the name is taken as a
    /// username already, a number is added.
    fn fill_usernames(&mut self) -> rusqlite::Result<()> {
        let missing: Vec<(String, String)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT email, name FROM accounts WHERE username IS NULL")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (email, name) in missing {
            let base = username_from(&name);
            let mut candidate = base.clone();
            let mut n = 2;
            while self.username_taken(&candidate)? {
                candidate = format!("{base}{n}");
                n += 1;
            }
            self.conn.execute(
                "UPDATE accounts SET username = ?1 WHERE email = ?2",
                params![candidate, email],
            )?;
        }
        Ok(())
    }

    pub fn username_taken(&self, username: &str) -> rusqlite::Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM accounts WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Sets the display name for the account with this (hashed) email. Returns `false` if the
    /// name is already used by another account.
    pub fn set_display_name(&self, email_hash: &str, name: &str) -> rusqlite::Result<bool> {
        constraint_ok(self.conn.execute(
            "UPDATE accounts SET name = ?1 WHERE email = ?2",
            params![name, email_hash],
        ))
    }

    /// The bio and banner colour of the account with this (hashed) email.
    pub fn about(&self, email_hash: &str) -> rusqlite::Result<(String, String)> {
        self.conn.query_row(
            "SELECT COALESCE(bio, ''), COALESCE(banner, '') FROM accounts WHERE email = ?1",
            params![email_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
    }

    /// Sets the status text of the account with this (hashed) email.
    /// Saves the servers (addresses, one per line) that the account with this (hashed) email is in.
    pub fn set_servers(&self, email_hash: &str, servers: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE accounts SET servers = ?2 WHERE email = ?1",
            params![email_hash, servers],
        )?;
        Ok(())
    }

    /// The servers (addresses, one per line) of the account with this (hashed) email. Empty when none are known.
    pub fn servers_for_email(&self, email_hash: &str) -> rusqlite::Result<String> {
        Ok(self
            .conn
            .query_row(
                "SELECT COALESCE(servers, '') FROM accounts WHERE email = ?1",
                params![email_hash],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default())
    }

    /// The servers (addresses, one per line) of the account with this id. Empty when none are known.
    pub fn servers_for_id(&self, id: &str) -> rusqlite::Result<String> {
        Ok(self
            .conn
            .query_row(
                "SELECT COALESCE(servers, '') FROM accounts WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default())
    }

    pub fn set_status_text(&self, email_hash: &str, text: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE accounts SET status_text = ?2 WHERE email = ?1",
            params![email_hash, text],
        )?;
        Ok(())
    }

    /// Sets the bio and banner colour of the account with this (hashed) email.
    pub fn set_about(&self, email_hash: &str, bio: &str, banner: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE accounts SET bio = ?2, banner = ?3 WHERE email = ?1",
            params![email_hash, bio, banner],
        )?;
        Ok(())
    }

    /// The profile picture of the account with this (hashed) email, or empty for none.
    pub fn avatar(&self, email_hash: &str) -> rusqlite::Result<String> {
        self.conn.query_row(
            "SELECT COALESCE(avatar, '') FROM accounts WHERE email = ?1",
            params![email_hash],
            |row| row.get(0),
        )
    }

    /// Sets the profile picture of the account with this (hashed) email.
    pub fn set_avatar(&self, email_hash: &str, avatar: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE accounts SET avatar = ?2 WHERE email = ?1",
            params![email_hash, avatar],
        )?;
        Ok(())
    }

    /// The public card of the account with this id: name, username, bio, banner colour and picture.
    pub fn profile_card(
        &self,
        id: &str,
    ) -> rusqlite::Result<Option<(String, String, String, String, String, u64, String)>> {
        self.conn
            .query_row(
                "SELECT name, COALESCE(username, ''), COALESCE(bio, ''), COALESCE(banner, ''), COALESCE(avatar, ''), created, COALESCE(status_text, '') FROM accounts WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get::<_, i64>(5)?.max(0) as u64, row.get(6)?)),
            )
            .optional()
    }

    /// Sets the username for the account with this (hashed) email. Returns `false` if it is taken.
    pub fn set_username(&self, email_hash: &str, username: &str) -> rusqlite::Result<bool> {
        constraint_ok(self.conn.execute(
            "UPDATE accounts SET username = ?1 WHERE email = ?2",
            params![username, email_hash],
        ))
    }

    /// Accounts and sessions still holding a plain email (from before emails were hashed) are
    /// rewritten as hashes. Returns how many addresses were converted.
    pub fn hash_plain_emails(&mut self) -> rusqlite::Result<usize> {
        let plain: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT email FROM accounts WHERE instr(email, '@') > 0
                 UNION SELECT email FROM sessions WHERE instr(email, '@') > 0",
            )?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let tx = self.conn.transaction()?;
        for email in &plain {
            let hashed = hash_email(&self.key, email);
            tx.execute(
                "UPDATE accounts SET email = ?1 WHERE email = ?2",
                params![hashed, email],
            )?;
            tx.execute(
                "UPDATE sessions SET email = ?1 WHERE email = ?2",
                params![hashed, email],
            )?;
        }
        tx.commit()?;
        Ok(plain.len())
    }

    /// Accounts whose email is already hashed. These need the key file to log in.
    pub fn hashed_account_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM accounts WHERE instr(email, '@') = 0", [], |row| {
                row.get(0)
            })
    }

    pub fn find_account(&self, email: &str) -> rusqlite::Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT name, password_hash FROM accounts WHERE email = ?1",
                params![hash_email(&self.key, email)],
                |row| {
                    Ok(Account {
                        name: row.get(0)?,
                        password_hash: row.get(1)?,
                    })
                },
            )
            .optional()
    }

    /// Creates an account. Returns `false` if the email or the name is already taken.
    pub fn create_account(
        &self,
        name: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        now: u64,
    ) -> rusqlite::Result<bool> {
        let id: [u8; 16] = rand::random();
        let result = self.conn.execute(
            "INSERT INTO accounts (id, email, name, username, password_hash, created, email_enc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                hex(&id),
                hash_email(&self.key, email),
                name,
                username,
                password_hash,
                now as i64,
                self.encrypt_email(email)
            ],
        );
        constraint_ok(result)
    }

    /// The account a session token belongs to, if the token is valid.
    /// The account with this display name, as `(id, name)`.
    pub fn account_by_name(&self, name: &str) -> rusqlite::Result<Option<(String, String)>> {
        self.conn
            .query_row("SELECT id, name FROM accounts WHERE name = ?1", params![name], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
    }

    /// Records that an account was seen connected at a server address.
    pub fn record_location(&self, account: &str, addr: &str, now: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO locations (account, addr, seen) VALUES (?1, ?2, ?3)
             ON CONFLICT (account, addr) DO UPDATE SET seen = excluded.seen",
            params![account, addr, now as i64],
        )?;
        Ok(())
    }

    /// The servers an account was last seen at, most recent first.
    pub fn locations_of(&self, account: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT addr FROM locations WHERE account = ?1 ORDER BY seen DESC LIMIT 5")?;
        let rows = stmt.query_map(params![account], |row| row.get(0))?;
        rows.collect()
    }

    pub fn session_account(&self, token: &str) -> rusqlite::Result<Option<SessionAccount>> {
        self.conn
            .query_row(
                "SELECT accounts.id, accounts.email, accounts.name, accounts.username,
                        accounts.password_hash, accounts.email_enc
                 FROM sessions JOIN accounts ON accounts.email = sessions.email
                 WHERE sessions.token = ?1",
                params![token],
                |row| {
                    Ok(SessionAccount {
                        id: row.get(0)?,
                        email_hash: row.get(1)?,
                        name: row.get(2)?,
                        username: row.get(3)?,
                        password_hash: row.get(4)?,
                        email_enc: row.get(5)?,
                    })
                },
            )
            .optional()
    }

    /// The email an account was stored with, decrypted. `None` for accounts made before emails
    /// were kept this way, which have no encrypted copy.
    pub fn account_email(&self, account: &SessionAccount) -> Option<String> {
        let enc = account.email_enc.as_deref()?;
        let (nonce_hex, cipher_hex) = enc.split_once(':')?;
        let nonce = unhex(nonce_hex)?;
        let cipher = unhex(cipher_hex)?;
        let key = chacha20poly1305::Key::from_slice(&self.key);
        let plain = ChaCha20Poly1305::new(key)
            .decrypt(Nonce::from_slice(&nonce), cipher.as_slice())
            .ok()?;
        String::from_utf8(plain).ok()
    }

    /// Replaces the account's email and every session's email. Returns `false` if the new email
    /// is already used by another account.
    pub fn change_email(&mut self, old_hash: &str, new_email: &str) -> rusqlite::Result<bool> {
        let new_hash = hash_email(&self.key, new_email);
        let enc = self.encrypt_email(new_email);
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "UPDATE accounts SET email = ?1, email_enc = ?2 WHERE email = ?3",
            params![new_hash, enc, old_hash],
        );
        match changed {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation => return Ok(false),
            Err(e) => return Err(e),
        }
        tx.execute(
            "UPDATE sessions SET email = ?1 WHERE email = ?2",
            params![new_hash, old_hash],
        )?;
        // A new address has to be confirmed again, and any code sent to the old one no longer counts.
        tx.execute("UPDATE accounts SET verified = 0 WHERE email = ?1", params![new_hash])?;
        tx.execute("DELETE FROM email_codes WHERE email_hash = ?1", params![old_hash])?;
        tx.commit()?;
        Ok(true)
    }

    /// True once the account has confirmed its email address.
    pub fn is_verified(&self, email_hash: &str) -> rusqlite::Result<bool> {
        let verified: i64 = self.conn.query_row(
            "SELECT verified FROM accounts WHERE email = ?1",
            params![email_hash],
            |row| row.get(0),
        )?;
        Ok(verified != 0)
    }

    pub fn set_verified(&self, email_hash: &str, verified: bool) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE accounts SET verified = ?2 WHERE email = ?1",
            params![email_hash, verified as i64],
        )?;
        Ok(())
    }

    /// The code waiting to be confirmed: (hashed code, expires, wrong tries, when it was sent).
    pub fn pending_code(&self, email_hash: &str) -> rusqlite::Result<Option<(String, u64, u32, u64)>> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row(
                "SELECT code_hash, expires, attempts, sent FROM email_codes WHERE email_hash = ?1",
                params![email_hash],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u32,
                        row.get::<_, i64>(3)? as u64,
                    ))
                },
            )
            .optional()
    }

    /// Stores a new code, replacing any earlier one, with no wrong tries yet.
    pub fn store_code(&self, email_hash: &str, code_hash: &str, expires: u64, sent: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO email_codes (email_hash, code_hash, expires, attempts, sent) VALUES (?1, ?2, ?3, 0, ?4)",
            params![email_hash, code_hash, expires as i64, sent as i64],
        )?;
        Ok(())
    }

    pub fn count_wrong_code(&self, email_hash: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE email_codes SET attempts = attempts + 1 WHERE email_hash = ?1",
            params![email_hash],
        )?;
        Ok(())
    }

    pub fn clear_code(&self, email_hash: &str) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM email_codes WHERE email_hash = ?1", params![email_hash])?;
        Ok(())
    }

    /// The email, encrypted with the account key as `nonce:ciphertext` in hex.
    fn encrypt_email(&self, email: &str) -> String {
        let nonce: [u8; 12] = rand::random();
        let key = chacha20poly1305::Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key)
            .encrypt(Nonce::from_slice(&nonce), email.as_bytes())
            .unwrap_or_default();
        format!("{}:{}", hex(&nonce), hex(&cipher))
    }

    pub fn create_session(&self, token: &str, email: &str, now: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (token, email, created) VALUES (?1, ?2, ?3)",
            params![token, hash_email(&self.key, email), now as i64],
        )?;
        Ok(())
    }

    /// Starts a session for the account with this id. Used for Discord logins, which find the
    /// account by its id, so the session follows it even after its email changes.
    pub fn create_account_session(&self, token: &str, account_id: &str, now: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (token, email, created)
             SELECT ?1, email, ?3 FROM accounts WHERE id = ?2",
            params![token, account_id, now as i64],
        )?;
        Ok(())
    }

    /// Sets the password hash of the account with this (hashed) email.
    pub fn set_password_hash(&self, email_hash: &str, password_hash: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE accounts SET password_hash = ?2 WHERE email = ?1",
            params![email_hash, password_hash],
        )?;
        Ok(())
    }

    /// Removes the account with this (hashed) email, with its sessions, Discord link, pending codes
    /// and recorded locations, in one step.
    pub fn delete_account(&mut self, email_hash: &str) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        let id: Option<String> = tx
            .query_row("SELECT id FROM accounts WHERE email = ?1", params![email_hash], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(id) = id {
            tx.execute("DELETE FROM discord_links WHERE account = ?1", params![id])?;
            tx.execute("DELETE FROM locations WHERE account = ?1", params![id])?;
        }
        tx.execute("DELETE FROM sessions WHERE email = ?1", params![email_hash])?;
        tx.execute("DELETE FROM email_codes WHERE email_hash = ?1", params![email_hash])?;
        tx.execute("DELETE FROM accounts WHERE email = ?1", params![email_hash])?;
        tx.commit()
    }

    /// The account id linked to this Discord account, if any.
    pub fn discord_account(&self, discord_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT account FROM discord_links WHERE discord_id = ?1",
                params![discord_id],
                |row| row.get(0),
            )
            .optional()
    }

    /// Links a Discord account to an account. `label` is the Discord name to show in settings.
    pub fn link_discord(&self, discord_id: &str, account_id: &str, label: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO discord_links (discord_id, account, label) VALUES (?1, ?2, ?3)",
            params![discord_id, account_id, label],
        )?;
        Ok(())
    }

    /// The Discord name linked to the account with this id, if any.
    pub fn linked_discord_label(&self, account_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT label FROM discord_links WHERE account = ?1",
                params![account_id],
                |row| row.get(0),
            )
            .optional()
    }

    /// Removes the Discord link of the account with this id.
    pub fn unlink_discord(&self, account_id: &str) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM discord_links WHERE account = ?1", params![account_id])?;
        Ok(())
    }

    /// The display name of the account with this id.
    pub fn name_of_account(&self, account_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row("SELECT name FROM accounts WHERE id = ?1", params![account_id], |row| {
                row.get(0)
            })
            .optional()
    }

    /// The id, display name and confirmed flag of the account with this email.
    pub fn account_by_email(&self, email: &str) -> rusqlite::Result<Option<(String, String, bool)>> {
        self.conn
            .query_row(
                "SELECT id, name, verified FROM accounts WHERE email = ?1",
                params![hash_email(&self.key, email)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
            )
            .optional()
    }

    /// Creates an account for a Discord login. Its email is already confirmed by Discord, and it has
    /// no password, so password login can never reach it. Returns the new id, or `None` when the
    /// name, username or email is taken.
    pub fn create_discord_account(
        &self,
        name: &str,
        username: &str,
        email: &str,
        now: u64,
    ) -> rusqlite::Result<Option<String>> {
        if !self.create_account(name, username, email, "", now)? {
            return Ok(None);
        }
        self.set_verified(&hash_email(&self.key, email), true)?;
        self.conn
            .query_row(
                "SELECT id FROM accounts WHERE email = ?1",
                params![hash_email(&self.key, email)],
                |row| row.get(0),
            )
            .optional()
    }

    /// The display name a session token belongs to, if the token is valid.
    /// The stored TLS certificate and key (PEM), if one has been made.
    pub fn tls_identity(&self) -> rusqlite::Result<Option<(String, String)>> {
        self.conn
            .query_row("SELECT cert, key FROM tls_identity WHERE id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
    }

    pub fn store_tls_identity(&self, cert: &str, key: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO tls_identity (id, cert, key) VALUES (1, ?1, ?2)",
            params![cert, key],
        )?;
        Ok(())
    }

    pub fn delete_session(&self, token: &str) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/db.rs"]
mod tests;
