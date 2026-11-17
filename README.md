# Vaxelium: auth

The auth service. It owns every Vaxelium account and login session, so one account works on
every chat server. Chat servers ask it who a session token belongs to. They never store
accounts.

It keeps accounts in SQLite, hashes passwords with Argon2, and can sign people in with
Discord and send email codes through Resend.

## Running

```
auth [ADDR] [DB_PATH]
```

- `ADDR` defaults to `127.0.0.1:7900`.
- `DB_PATH` defaults to `auth.db`. The email key is stored next to it, as `auth.db.key`.

The service makes its own TLS certificate the first time it runs. Chat servers and
clients pin it.

Settings are read from a `.env` file in the folder it starts in. See the main repository's
`.env.example`. Set `RESEND_API_KEY` to send email codes. Set the Discord values to allow
"Log in with Discord".

## Part of Vaxelium

This repository is one part of the Vaxelium project. The rest are linked from the main
repository:

- [Vaxelium](https://github.com/Vaxelium/Vaxelium): the workspace, build scripts and docs
- [common](https://github.com/Vaxelium/common): the wire protocol shared by every part
- [server](https://github.com/Vaxelium/server): the chat server and its web client host
- [client](https://github.com/Vaxelium/client): the desktop and web client

## Building

Build it from the main repository, because this crate depends on `common` by relative path:

```
git clone --recursive git@github.com:Vaxelium/Vaxelium.git
cd Vaxelium
cargo run -p auth
```

## Licence

GNU GPL v3. See [LICENSE](LICENSE).
