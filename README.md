# Secure_P2P_Files
A secure method to share files over a local network. Clients written in both Python and C#.

# Preliminaries
For the Python client, you will need to have ```cryptography``` and ```zeroconf``` installed: ```pip install zeroconf```, ```pip install cryptography```.

For the C# client, follow the instructions below:

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

# Running tests
## Python tests
To run Python tests, ```cd``` into the ```Python``` directory and run ```python3 test.py```. The test suite covers message serialization/deserialization, message framing & AES-GCM encryption/decryption, signature verification, file encryption/decryption, key derivation, the handshake, and key migration.

## C# tests
To run C# tests, from the `Dotnet/` directory:

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


# Running the project

## Python
To run the Python client, ```cd``` into the ```Python``` directory containing the Python files, and run ```python3 client.py```. You may choose to create additional test files in ```shared_data/``` before running. By default the Python client runs its mDNS server on port 5000; if you wish to change this, you can do so by making the following changes in ```client.py```:

- Change line 455 from ```srv.bind(("0.0.0.0", 5000))``` to ```srv.bind(("0.0.0.0", <port_of_your_choice>))```
- Change line 489 from ```disc = Discovery(fingerprint, port=5000)``` to ```disc = Discovery(fingerprint, port=<port_of_your_choice>)```

If you wish to run two Python clients peering with each other, you can copy the ```Python`` directory (so the files don't get mixed up) to another directory, change the port number for this new version of the Python client as described above, and run the second client in another terminal.

## C#
For the C# client, follow the instructions below:

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

# Notes
The project is imperfect, so please note that running end-to-end with two clients may require pressing ```Enter``` a few times to get output to appear in the console.
