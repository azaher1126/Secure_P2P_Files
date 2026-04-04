# SecureFiles — .NET P2P File Sharing

A secure, local peer-to-peer file sharing application built on .NET 10. Peers on the same LAN discover each other automatically via mDNS/DNS-SD and exchange files over an encrypted channel - no server required.

## What it does

- **Peer discovery** — advertises itself and discovers other instances on the local network using mDNS (Multicast DNS) under the `_securep2pfiles._tcp` service type.
- **Secure handshake** — establishes an encrypted session using an X25519 ephemeral key exchange signed with each peer's long-term RSA-2048 identity key.
- **Encrypted transport** — all messages are encrypted with AES-256-GCM after the handshake; each message carries a random 96-bit nonce and a 128-bit authentication tag.
- **File integrity** — received files are verified against a SHA-256 hash and an RSA-PSS signature that covers `UTF8(filename) || SHA256(fileData)`.
- **Consent model** — the receiving peer must explicitly accept or deny every incoming file request before any data is sent.
- **Key migration** — users can rotate their long-term RSA identity key; the new key is announced to active peers, signed by the old key, with a replay nonce to prevent replay attacks.
- **Interactive TUI** — a terminal-based UI (built with Spectre.Console) lets you browse peers, view shared files, send/receive files, and manage contacts.

## Installing .NET 10

Use the official Microsoft installation script to install .NET for the current user without requiring root:

```bash
curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 10.0
```

Then add the SDK to your `PATH` by appending these lines to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$PATH:$HOME/.dotnet:$HOME/.dotnet/tools"
```

Reload your shell or run `source ~/.zshrc` (or equivalent), then verify:

```bash
dotnet --version
```

## Running the application

From the `Dotnet/` directory:

```bash
dotnet run --project SecureFiles/SecureFiles.csproj
```

On first run you will be prompted to create a username and password. Your RSA identity key pair is generated and the private key is stored encrypted on disk (see [Security choices](#security-choices)).

**Optional flag:**

| Flag | Description |
|------|-------------|
| `--data-directory <path>` | Override the directory where keys, the file index, contacts, and logs are stored. Defaults to a platform-appropriate user data folder. |

Example with a custom data directory:

```bash
dotnet run --project SecureFiles/SecureFiles.csproj -- --data-directory /tmp/alice
```

Run a second instance in another terminal with a different directory to simulate a second peer:

```bash
dotnet run --project SecureFiles/SecureFiles.csproj -- --data-directory /tmp/bob
```

## Running the tests

From the `Dotnet/` directory:

```bash
dotnet test SecureFiles.Tests/SecureFiles.Tests.csproj
```

The test suite (xUnit v3) covers:

- Message serialisation/deserialisation for all wire message types (`FileRequestMessage`, `FileListResponseMessage`, `ConsentResponseMessage`, `DataTransferMessage`, `KeyMigrationMessage`)
- `MessageFramer` framing and AES-GCM encryption/decryption round-trips
- `SignatureVerifier` RSA-PSS file signature verification
- `UserConfigProvider` key persistence and PBKDF2 key derivation
- Key migration message signature verification and replay-nonce detection
- Peer fingerprint computation

## Security choices

### Identity keys — RSA-2048 with PSS padding

Each user has a long-term RSA-2048 key pair generated on first launch. RSA-PSS (with SHA-256) is used for all signatures. The private key is never sent over the network.

### Private key encryption at rest

The private key is stored on disk encrypted with AES-256 using a key derived from the user's password via **PBKDF2-SHA256 with 600,000 iterations** and a random per-user salt. This makes offline brute-force attacks expensive.

### Ephemeral key exchange — X25519 + HKDF

For each connection a fresh X25519 key pair is generated. The peer's long-term RSA key signs its X25519 public value so the exchange is authenticated. The shared secret is never used directly; it is passed through **HKDF-SHA256** (with a fixed application salt and `"SessionKey"` info label) to produce the 256-bit AES-GCM session key. The raw shared secret is zeroed from memory immediately after derivation.

### Confidentiality and integrity — AES-256-GCM

Every message after the handshake is encrypted with AES-256-GCM. Each message carries a freshly generated 96-bit random nonce and a 128-bit authentication tag. Decryption failure (tampered ciphertext or wrong key) raises a `CryptographicException` and terminates the session.

### Session expiry

Sessions automatically expire after **5 minutes** of inactivity. Any attempt to send or receive on an expired session is rejected before touching the network.

### File integrity verification

After a file is received, the application verifies:
1. The SHA-256 hash of the file data matches the hash in the metadata.
2. The RSA-PSS signature over `UTF8(filename) || SHA256(fileData)` is valid for the file owner's public key.

A file that fails either check is rejected and not saved to disk.

### Explicit consent

Before transferring any file (in either direction), the receiving peer must explicitly accept the request through the TUI. No data is sent until consent is granted.

### Key migration with replay protection

When a user rotates their identity key, the migration message contains a 16-byte random replay nonce. The receiver tracks all seen nonces and rejects any message whose nonce has been used before, preventing replay attacks. The new key is only trusted after the migration message signature (under the old key) is verified.

### Peer fingerprinting

Each peer is identified by the first 8 bytes (16 hex characters) of the SHA-256 hash of their RSA public key in SPKI-DER form. This fingerprint is used as the mDNS service instance name and as the key in the local contact store.
