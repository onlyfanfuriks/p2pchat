# p2pchat

Peer-to-peer encrypted terminal chat over the [Yggdrasil](https://yggdrasil-network.github.io/) IPv6 mesh network. No servers, no accounts on third-party services — just direct encrypted connections between peers.

## Features

- **End-to-end encryption** — X25519 ECDH key exchange, AES-256-GCM message encryption, Ed25519 signatures
- **No central server** — peers connect directly over Yggdrasil mesh networking
- **Encrypted storage** — account file (AES-256-GCM) and message database (SQLCipher)
- **Offline messaging** — messages queued and retried automatically when peer comes online
- **Terminal UI** — rich Textual-based interface with contacts, chat history, delivery indicators
- **Zero configuration** — auto-downloads Yggdrasil, generates keys, persists everything

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
2. If Yggdrasil is not found in PATH, it downloads v0.5.13 automatically from GitHub releases
3. You set a **display name** and **password** (encrypts your account and database)
4. Keys are generated (Ed25519 identity + X25519 encryption)
5. Yggdrasil starts, you get a persistent IPv6 address

### Troubleshooting

If the status bar stays on "yggdrasil starting…" or shows an error:

- **Run as root** (or use `sudo`) — Yggdrasil needs to create a TUN network interface:

  ```bash
  sudo p2pchat
  ```

- **Or grant the capability** so you don't need root every time:

  ```bash
  sudo setcap cap_net_admin=eip $(which yggdrasil)
  # or if using the auto-downloaded binary:
  sudo setcap cap_net_admin=eip ~/.config/p2pchat/bin/yggdrasil
  ```

- **Check if Yggdrasil is already running** system-wide — two instances will conflict:

  ```bash
  sudo systemctl stop yggdrasil   # stop system service
  ```

- **Firewall**: ensure outbound TCP/TLS traffic is allowed — the app connects to public peers on various ports
- **Logs**: check `~/.config/p2pchat/p2pchat.log` for detailed error output

### Connecting to a peer

1. Press **Ctrl+I** to show your invite link
2. Share it with your peer via any channel (email, Signal, etc.)
3. Your peer presses **Ctrl+O** and pastes your invite link
4. On first connection, both sides verify each other's fingerprint
5. Once verified, the contact is saved and you can chat

### Invite link format

```
p2pchat://[200:abcd::1234]:7331/BASE64URL_ED25519_PUBKEY#DisplayName
```

## Keybindings

| Key        | Action                          |
| ---------- | ------------------------------- |
| **Ctrl+I** | Show your invite link           |
| **Ctrl+O** | Open/paste a peer's invite link |
| **Ctrl+D** | Delete selected conversation    |
| **Tab**    | Toggle contact list             |
| **Escape** | Focus message input             |
| **Enter**  | Send message                    |

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

## Security notes

- **File permissions**: Account, database, and TLS keys are `0600`. Config directory is `0700`.
- **Brute-force protection**: Max 5 password attempts, then 30-second cooldown.
- **Binary validation**: Auto-downloaded Yggdrasil binary is checked for ownership and symlink attacks.
- **Connection limits**: Max 64 concurrent connections to prevent DoS.
- **Atomic writes**: Account and config files use temp-then-rename to prevent corruption.
- **TLS hardening**: Compression disabled (CRIME mitigation), session tickets disabled.

## License

Proprietary. See [LICENSE](LICENSE) for details.
