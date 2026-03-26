# p2pchat

Peer-to-peer encrypted terminal chat over the [Yggdrasil](https://yggdrasil-network.github.io/) IPv6 mesh network. No servers, no accounts on third-party services — just direct encrypted connections between peers.

## Features

- **End-to-end encryption** — X25519 ECDH key exchange, AES-256-GCM message encryption, Ed25519 signatures
- **No central server** — peers connect directly over Yggdrasil mesh networking
- **Encrypted storage** — account file (AES-256-GCM) and message database (SQLCipher)
- **Offline messaging** — messages queued and retried automatically when peer comes online
- **Terminal UI** — rich Textual-based interface with contacts, chat history, delivery indicators
- **Zero configuration** — auto-downloads Yggdrasil or attaches to a system service, generates keys, persists everything
- **Themes** — 11 built-in color themes (dark and light), switchable via command palette
- **Help system** — context-sensitive keybinding help (F1) on every screen
- **Command palette** — Ctrl+P for quick actions (download Yggdrasil, switch theme, etc.)

## Requirements

- **Python 3.13+**
- **Linux** (x86_64, aarch64, armv7l) or **macOS** (x86_64, arm64)
- **Root or CAP_NET_ADMIN** — Yggdrasil needs permission to create a TUN interface
- On macOS: install Yggdrasil manually (`brew install yggdrasil`) — auto-download is Linux-only

## Installation

### uv (recommended)

```bash
uv tool install git+https://github.com/onlyfanfuriks/p2pchat.git
```

### pipx

```bash
pipx install git+https://github.com/onlyfanfuriks/p2pchat.git
```

### pip

```bash
git clone https://github.com/onlyfanfuriks/p2pchat.git && cd p2pchat
pip install .
```

### Development

```bash
git clone https://github.com/onlyfanfuriks/p2pchat.git && cd p2pchat
uv sync          # or: poetry install
```

## Usage

```bash
p2pchat
```

Or via Python module:

```bash
python -m p2pchat
```

### First run

1. The app creates `~/.config/p2pchat/` for all data
2. You set a **display name** and **password** (encrypts your account and database)
3. Keys are generated (Ed25519 identity + X25519 encryption)
4. Yggdrasil starts — the app auto-detects the best option:
   - **System service** — if Yggdrasil is already running (e.g. `systemctl start yggdrasil`), the app attaches to it automatically via admin socket or network interface detection
   - **Standalone subprocess** — if no system instance is found, the app starts its own Yggdrasil process
   - **Auto-download** — if the binary isn't installed, download it via command palette (Ctrl+P → "Download Yggdrasil")
5. You get a persistent IPv6 address

### Yggdrasil modes

The app supports two ways to run Yggdrasil:

#### Use a system service (recommended)

If you already run Yggdrasil as a system service, p2pchat will detect it automatically — no extra setup needed. This is the simplest option:

```bash
sudo systemctl enable --now yggdrasil
p2pchat   # no sudo needed — attaches to the running service
```

#### Standalone (app-managed subprocess)

If no system service is detected, the app starts its own Yggdrasil process. This requires TUN interface permissions:

```bash
sudo p2pchat
```

Or grant the capability once so you don't need `sudo` every time:

```bash
sudo setcap cap_net_admin=eip $(which yggdrasil)
# or for the auto-downloaded binary:
sudo setcap cap_net_admin=eip ~/.config/p2pchat/bin/yggdrasil
```

### Troubleshooting

If the status bar stays on "yggdrasil starting…" or shows an error:

- **No Yggdrasil binary?** Press **Ctrl+P** and select "Download Yggdrasil" — it downloads v0.5.13 from GitHub releases
- **Permission denied?** Run with `sudo` or grant `cap_net_admin` (see above)
- **Firewall**: ensure outbound TCP/TLS traffic is allowed — the app connects to public peers on various ports
- **Logs**: check `~/.config/p2pchat/p2pchat.log` for detailed error output

### Connecting to a peer

1. Press **Ctrl+N** to show your invite link
2. Share it with your peer via any channel (email, Signal, etc.)
3. Your peer presses **Ctrl+O** and pastes your invite link
4. On first connection, both sides verify each other's fingerprint
5. Once verified, the contact is saved and you can chat

### Invite link format

```
p2pchat://[200:abcd::1234]:7331/BASE64URL_ED25519_PUBKEY#DisplayName
```

## Keybindings

### Chat screen

| Key                          | Action                          |
| ---------------------------- | ------------------------------- |
| **F1**                       | Context-sensitive help          |
| **Ctrl+P**                   | Command palette                 |
| **Ctrl+Q**                   | Quit                            |
| **Enter**                    | Send message                    |
| **Ctrl+Enter / Shift+Enter** | New line in message             |
| **Escape**                   | Focus message input             |
| **Tab**                      | Toggle contact list             |
| **Ctrl+N**                   | Show your invite link           |
| **Ctrl+O**                   | Connect to peer (paste invite)  |
| **Ctrl+D**                   | Delete contact and chat history |
| **Ctrl+B**                   | Backup info                     |
| **Ctrl+W**                   | Wipe data info                  |

### Account screen

| Key        | Action             |
| ---------- | ------------------ |
| **F1**     | Help               |
| **Escape** | Go back            |
| **Enter**  | Submit             |
| **Ctrl+N** | Create new account |
| **F8**     | Delete account     |

## How it works

### Network

Peers connect over Yggdrasil's encrypted IPv6 mesh network on **port 7331**. Connections use TLS 1.2+ with self-signed certificates — peer identity is verified at the application layer via Ed25519 signatures, not certificate authorities.

Messages are length-prefixed JSON frames (4-byte big-endian length + body, max 4 MB). Keepalive pings are sent every 30 seconds.

### Encryption

| Layer         | Algorithm                              | Purpose                        |
| ------------- | -------------------------------------- | ------------------------------ |
| Account file  | AES-256-GCM + PBKDF2 (600k iterations) | Encrypt keys at rest           |
| Database      | SQLCipher (AES-256)                    | Encrypt message history        |
| Key exchange  | X25519 ECDH + HKDF-SHA256              | Per-session shared secret      |
| Messages      | AES-256-GCM + Ed25519 signatures       | Confidentiality + authenticity |
| Offline queue | X25519 + AES-256-GCM                   | Pre-encrypt for offline peers  |

Each session uses **ephemeral X25519 keypairs** so that compromising one session doesn't compromise others.

### Identity verification

On first connection to an unknown peer, you're shown their Ed25519 fingerprint (SHA-256 hash, colon-separated hex). Verify this out-of-band (phone call, in person) to confirm you're talking to the right person. Once verified, the contact is marked trusted and future connections are automatic.

### Offline messages

If a peer is offline, messages are encrypted with their long-term X25519 public key and stored in the outbox. The app retries delivery with exponential backoff (30s → 60s → 120s → 300s → 600s). A ⏳ indicator shows pending messages; ✓ appears when delivered.

## File structure

All data lives in `~/.config/p2pchat/`. Each account gets its own subdirectory:

```
~/.config/p2pchat/
├── p2pchat.log                # Application log (shared)
├── bin/
│   └── yggdrasil              # Auto-downloaded binary (if not in PATH)
└── accounts/
    └── <display_name>/        # Per-account directory
        ├── account.json       # Encrypted keypairs and identity
        ├── messages.db        # SQLCipher encrypted message database
        ├── tls.crt            # Self-signed TLS certificate
        ├── tls.key            # TLS private key
        ├── ygg_run.conf       # Yggdrasil runtime config
        └── ygg.sock           # Yggdrasil admin socket
```

All sensitive files are created with `0600` permissions. The config directory itself is `0700`.

## Testing

```bash
uv run pytest tests/
uv run pytest tests/ --cov    # with coverage
uv run ruff check .           # lint
```

## Themes

11 built-in themes available via command palette (**Ctrl+P** → "Change theme"):

**Dark:** galaxy, nebula, sunset, aurora, nautilus, cobalt, twilight, hacker, hypernova, synthwave
**Light:** manuscript

## Security notes

- **File permissions**: Account, database, and TLS keys are `0600`. Config directory is `0700`.
- **Brute-force protection**: Max 5 password attempts, then 30-second cooldown.
- **Binary validation**: Auto-downloaded Yggdrasil .deb is verified via SHA-256 checksum; user-dir binaries are checked for ownership and symlink attacks.
- **Secure account deletion**: F8 on unlock screen with typed confirmation phrase; files are overwritten before removal.
- **Connection limits**: Max 64 concurrent connections to prevent DoS.
- **Atomic writes**: Account and config files use temp-then-rename to prevent corruption.
- **TLS hardening**: Compression disabled (CRIME mitigation), session tickets disabled.
- **Keepalive**: Ping/pong every 30s; stale connections are dropped automatically.

## License

Proprietary. See [LICENSE](LICENSE) for details.
