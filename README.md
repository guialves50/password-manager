# Guardian

**A zero-knowledge password manager for the terminal.** Your vault is encrypted on your machine; the server only ever stores opaque blobs.

Guardian is a Go client/server password manager with an animated terminal UI. The master password never leaves your device, the server cannot read your item names or passwords, and TOTP two-factor authentication works with Google Authenticator and Microsoft Authenticator.

```
 >_ Guardian (v0.1.0)
     http://127.0.0.1:8080 · ana@example.com

  ⢠⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⡄
  ⢸ cofre · 3 itens                        ⡇
  ⢸                                        ⡇
  ⢸   Amazon                               ⡇
  ⢸ › GitHub                               ⡇
  ⢸   Gmail                                ⡇
  ⢸                                        ⡇
  ⢸ ↑↓ navegar · enter abrir · esc sair    ⡇
  ⠘⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠃
```

> [!NOTE]
> The interface text is in Brazilian Portuguese. Commands (`login`, `add`, `list`, …) are in English.

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Security notes and limitations](#security-notes-and-limitations)
- [Contributing](#contributing)

## Features

- **Client-side encryption.** Every vault item, including its name, is encrypted with AES-256-GCM before it leaves the client.
- **Master password never sent.** The client derives keys with Argon2id and sends only a derived authentication hash.
- **Recovery key.** A one-time 160-bit recovery key resets a forgotten master password without losing the vault.
- **TOTP two-factor authentication** (RFC 6238), enrolled by scanning a QR code drawn in the terminal, with per-account and per-IP rate limiting and replay protection.
- **Brute-force protection.** 5 failed password attempts lock the account for 15 minutes.
- **Password generator** using `crypto/rand`, 8–128 characters (default 20), with at least one uppercase letter, lowercase letter, digit and symbol.
- **Animated terminal UI.** A rotating braille shield morphs into a box for every command, and into a check mark on success.
- **Works without the TUI.** `register`, `login` and `recover` run as plain subcommands that read from stdin. The vault commands run in the shell that `login` opens.

## How it works

Guardian is split into a **client** (CLI/TUI) and a **server** (`guardian serve`). Only the server talks to PostgreSQL, and it never sees anything that would let it decrypt the vault.

```mermaid
flowchart LR
    subgraph Client["Client (your machine)"]
        PW[Master password] -->|Argon2id| MK[Master key]
        MK -->|HKDF 'pm/auth/v1'| AH[Auth hash]
        MK -->|HKDF 'pm/enc/v1'| EK[Encryption key]
        EK -->|AES-256-GCM| VK[Vault key]
        VK -->|AES-256-GCM| Items[Encrypted items]
    end
    subgraph Server["Server (guardian serve)"]
        DB[(PostgreSQL)]
    end
    AH -->|login| Server
    Items -->|opaque blobs| Server
    Server --- DB
```

1. **Key derivation.** The client runs Argon2id (t=3, 64 MiB, 4 threads) over the master password and a per-user salt. It then splits the result with HKDF-SHA256 into an **auth hash**, which is sent to the server, and an **encryption key**, which never leaves the client.
2. **Vault key.** A random 256-bit vault key encrypts every item. It is stored on the server twice: wrapped by the master-password key and wrapped by a key derived from the recovery key.
3. **Server-side verification.** The server stores `Argon2id(authHash, serverSalt)`, never the auth hash itself. A database dump is not enough to log in.
4. **Items.** Each item is serialized and sealed with the vault key. The AAD (additional authenticated data) is `pm/item/v1|<userID>|<itemID>`, so blobs cannot be swapped between items or accounts. Item names are encrypted too, so search and duplicate checks happen on the client.
5. **Sessions.** Login returns a random 256-bit bearer token. The server stores only its SHA-256 hash, and sessions expire after 30 minutes without use.

### Two-factor authentication

- Inside the vault, run `2fa`. A QR code appears in place of the shield; scan it and type the 6-digit code to confirm.
- After that, login asks for the code once the master password is verified.
- The TOTP secret is stored encrypted with a key derived from `PM_SERVER_SECRET`.
- 3 wrong codes lock the account's 2FA for 10 minutes, and 3 wrong codes from one IP within 10 minutes block that IP for 10 minutes.
- A code that was already accepted is never accepted again.
- A successful `recover` disables 2FA, so losing your phone does not lock you out for good.

## Getting started

### Requirements

- Go 1.27 or newer
- Docker, for the bundled PostgreSQL 17, or any PostgreSQL instance

### 1. Start the database

```bash
docker compose up -d
```

PostgreSQL listens on `127.0.0.1:5433`. The schema is migrated automatically when the server starts.

### 2. Configure the server secret

`PM_SERVER_SECRET` must be 32 random bytes in hex. Without it, the server generates a new secret on every start, and **two-factor authentication is disabled**.

```bash
cp .env.example .env
sed -i.bak "s/^PM_SERVER_SECRET=.*/PM_SERVER_SECRET=$(openssl rand -hex 32)/" .env && rm .env.bak
```

> [!IMPORTANT]
> Guardian does not read `.env` by itself. Export it into **every** shell that runs Guardian, both the server and the client:
>
> ```bash
> set -a; source .env; set +a
> ```

### 3. Optional: TLS with a self-signed certificate

```bash
mkdir -p certs && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
  -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Then set these in `.env`. `certs/` is git-ignored.

```bash
PM_TLS_CERT=/absolute/path/to/certs/server.crt
PM_TLS_KEY=/absolute/path/to/certs/server.key
PM_SERVER=https://127.0.0.1:8080
PM_CA_CERT=/absolute/path/to/certs/server.crt
```

With TLS on, the server accepts HTTPS only. Load `.env` in the client's shell too, so the client uses `https://` and trusts the certificate.

### 4. Run the server

```bash
set -a; source .env; set +a
go run . serve
# servidor ouvindo em 127.0.0.1:8080
```

### 5. Build and run the client

In another terminal:

```bash
set -a; source .env; set +a
go build -o guardian .
./guardian
```

Running `guardian` with no arguments in a terminal opens the TUI. Type `register` to create an account, and save the recovery key it shows you: it is displayed only once.

> [!TIP]
> `./guardian` is a compiled binary. Run `go build -o guardian .` again after pulling changes, or the client keeps running the old code.

## Usage

### Home screen

| Command    | Description |
| ---------- | ----------- |
| `register` | Create an account (email + master password) and receive a recovery key. |
| `login`    | Open the vault. Asks for the 2FA code when enabled. |
| `recover`  | Set a new master password with the recovery key. Rotates the recovery key and disables 2FA. |
| `exit`     | Quit. |

### Inside the vault

| Command          | Description |
| ---------------- | ----------- |
| `add`            | Add an item with a generated password (name, username, length, URL, notes). |
| `list`           | Browse items in a box: <kbd>↑</kbd>/<kbd>↓</kbd> to move, <kbd>Enter</kbd> to open, <kbd>Space</kbd> to reveal the password, <kbd>Esc</kbd> to go back or close. |
| `get [name]`     | Show one item. Without a name, opens the list. |
| `delete [name]`  | Delete one item after confirmation. Without a name, pick it from the list. |
| `2fa`            | Enable two-factor authentication. |
| `exit`, `logout` | Close the vault. |

### Keyboard shortcuts

| Key                  | Action |
| -------------------- | ------ |
| <kbd>Enter</kbd>     | Submit |
| <kbd>Ctrl</kbd>+<kbd>C</kbd> | Cancel the current prompt (quits from the home screen) |
| <kbd>Ctrl</kbd>+<kbd>L</kbd> | Clear the screen |
| <kbd>Ctrl</kbd>+<kbd>U</kbd> | Clear the input line |
| <kbd>?</kbd>         | Toggle help |

### Without the TUI

Each home-screen command also runs as a subcommand, reading answers from stdin. After `guardian login`, the vault commands (`add`, `list`, `get <name>`, `delete <name>`) run in a plain `guardian>` shell.

```bash
guardian register
guardian login
guardian recover
```

## Configuration

All configuration comes from environment variables.

| Variable           | Used by | Default | Description |
| ------------------ | ------- | ------- | ----------- |
| `PM_SERVER`        | client  | `http://127.0.0.1:8080` | Server URL. Plain `http` is refused for anything other than localhost. |
| `PM_CA_CERT`       | client  | system roots | PEM certificate to trust instead of the system roots, e.g. a self-signed server certificate. |
| `PM_ADDR`          | server  | `127.0.0.1:8080` | Listen address. |
| `PM_SERVER_SECRET` | server  | random per start | 32 bytes in hex. Keeps decoy pre-login answers stable and encrypts TOTP secrets. **Required for 2FA.** |
| `PM_TLS_CERT`      | server  | — | TLS certificate file. Set together with `PM_TLS_KEY` (TLS 1.2+). |
| `PM_TLS_KEY`       | server  | — | TLS private key file. |
| `DATABASE_URL`     | server  | `postgres://postgres:postgres@localhost:5433/password_manager?sslmode=disable` | PostgreSQL connection string. |

## Project layout

```
.
├── main.go                  # entry point: TUI, subcommands and `serve`
└── src
    ├── api                  # HTTP client used by the CLI
    ├── cli                  # prompts, session shell, TUI hooks
    ├── database             # connection and migrations
    ├── modules
    │   ├── auth             # register, login, recover, prelogin, 2FA (totp, twofactor)
    │   ├── session          # bearer sessions and auth middleware
    │   ├── user             # user model and repository
    │   └── vault            # items (add/list/get/delete) and password generator
    ├── server               # HTTP mux, request limits and helpers
    └── tui                  # terminal UI: shield, box, QR code, animations
```

Each feature follows `dto / repository / services / controllers / handlers / router`:

- `services` and `controllers` run on the **client**.
- `handlers` and `repository` run on the **server**.

## Development

```bash
# unit tests
go test ./...

# unit + integration tests (needs the PostgreSQL from docker compose)
go test -tags=integration -p 1 ./...

# full check before a pull request
test -z "$(gofmt -l .)" && go vet -tags=integration ./... && go build ./... && go test -tags=integration -p 1 ./...
```

Integration tests run inside a transaction that is rolled back, so they leave the database unchanged.

## Troubleshooting

| Symptom | Cause | Fix |
| ------- | ----- | --- |
| Server prints `não foi possível preparar o banco de dados` | PostgreSQL is not running, often because Docker is stopped. | Start Docker, then `docker compose up -d`. |
| Server logs `client sent an HTTP request to an HTTPS server` | The client was started without `.env`, so it uses the default `http://` URL. | Run `set -a; source .env; set +a` in the client's shell. |
| Server logs `tls: bad certificate`, client shows `não foi possível conectar ao servidor` | The client does not trust the self-signed certificate: `PM_CA_CERT` is not set, or the binary is older than `PM_CA_CERT` support. | Load `.env` in the client's shell and rebuild with `go build -o guardian .`. |
| `2fa` shows `2FA indisponível: o servidor precisa de PM_SERVER_SECRET` | The server was started without `PM_SERVER_SECRET`. | Set it in `.env` and restart the server with `.env` loaded. |
| Login shows `o servidor não consegue ler seu 2FA` | 2FA was enabled while the server had a different (or no) `PM_SERVER_SECRET`, and that key is gone. | Run `recover` to disable 2FA, then enable it again with `2fa`. |

## Security notes and limitations

Guardian is a personal project and has **not been independently audited**. Known limits:

- **Rate limiting is per process.** The per-IP 2FA limiter lives in memory, so it resets on restart and is not shared between server instances. Account lockouts are stored in the database.
- **IP is the TCP peer address.** `X-Forwarded-For` is ignored on purpose, so behind a reverse proxy every client shares the proxy's IP.
- **Client-side search.** Every vault command decrypts the whole vault, which is O(n) in the number of items.
- **In-memory secrets.** The vault key is zeroed when the session ends, but Go strings, such as decrypted item fields, cannot be wiped from memory.

To report a vulnerability, please contact the maintainer privately instead of opening a public issue.

## Contributing

Issues and pull requests are welcome.

1. Fork the repository and create a branch from `main`.
2. Make your change with tests, and run the full check from [Development](#development).
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages, e.g. `feat(tui): …`, `fix(twofactor): …`.
4. Open a pull request describing what changed and how you tested it.
