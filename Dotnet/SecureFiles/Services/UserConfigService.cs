using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;
using Spectre.Console;

namespace SecureFiles.Services;

public class UserConfigService
{
    private const string ConfigFileName = "config";
    private const string SaltFileName = "local.salt";
    private const string PrivateKeyFileName = "identity.key";
    private const string PublicKeyFileName = "identity.pub";

    private readonly LocalFileService _localFileService;

    private UserConfig? _userConfig;
    private string? _password;

    public string Username => _userConfig?.Username
        ?? throw new InvalidOperationException("User config not loaded. Call LoadOrInitialize() first.");

    public byte[] PublicKey => _userConfig?.PublicKey
        ?? throw new InvalidOperationException("User config not loaded. Call LoadOrInitialize() first.");

    public byte[] PrivateKey => _userConfig?.PrivateKey
        ?? throw new InvalidOperationException("User config not loaded. Call LoadOrInitialize() first.");

    public string Password => _password
        ?? throw new InvalidOperationException("Password not set. Call LoadOrInitialize() first.");

    public string DataDirectory { get; }

    private string ConfigPath => Path.Combine(DataDirectory, ConfigFileName);
    private string SaltPath => Path.Combine(DataDirectory, SaltFileName);
    private string PrivateKeyPath => Path.Combine(DataDirectory, PrivateKeyFileName);
    private string PublicKeyPath => Path.Combine(DataDirectory, PublicKeyFileName);

    public UserConfigService(LocalFileService localFileService, string? dataDirectory = null, string? password = null)
    {
        _localFileService = localFileService;
        DataDirectory = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SecureFiles");
        
        _password = password;
    }

    /// <summary>
    /// Loads an existing config or runs first-time initialization.
    /// Returns false if the user chose not to proceed (e.g. declined a reset).
    /// </summary>
    public async Task<bool> LoadOrInitialize()
    {
        if (IsFullyInitialized())
            return await LoadExisting();

        if (IsPartiallyInitialized())
        {
            var reset = await AnsiConsole.ConfirmAsync(
                "Application data appears corrupt (some files are missing). Reset and reinitialize? This will delete all existing data.",
                defaultValue: false);

            if (!reset) return false;

            Directory.Delete(DataDirectory, true);
        }

        Directory.CreateDirectory(DataDirectory);
        return await InitializeNew();
    }

    /// <summary>
    /// Returns the 16-character lowercase hex fingerprint of the public key.
    /// Used as the mDNS instance name / Peer ID.
    /// </summary>
    public string GetFingerprint()
    {
        var hash = SHA256.HashData(PublicKey);
        return Convert.ToHexStringLower(hash[..8]);
    }

    /// <summary>
    /// Derives the AES-256 master key from the user's password and stored salt.
    /// Call this whenever you need the key — do not cache it long-term.
    /// </summary>
    public async Task<byte[]> DeriveAesKey(CancellationToken cancellationToken = default)
    {
        var salt = await File.ReadAllBytesAsync(SaltPath, cancellationToken);
        return Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(Password),
            salt: salt,
            iterations: 600_000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 32);
    }

    private async Task<bool> LoadExisting()
    {
        _password = await PromptExistingPassword();

        byte[] key;
        try
        {
            key = await DeriveAesKey();
        }
        catch
        {
            AnsiConsole.MarkupLine("[red]Failed to derive encryption key. The salt file may be corrupt.[/]");
            return false;
        }

        try
        {
            // identity.pub — plaintext SPKI DER
            var publicKey = await File.ReadAllBytesAsync(PublicKeyPath);

            // identity.key — encrypted private key
            var privateKey = await _localFileService.ReadEncryptedBytes(PrivateKeyPath, key);

            // config — encrypted username
            var usernameBytes = await _localFileService.ReadEncryptedBytes(ConfigPath, key);
            var username = Encoding.UTF8.GetString(usernameBytes);

            _userConfig = new UserConfig(username, publicKey, privateKey);
        }
        catch
        {
            AnsiConsole.MarkupLine("[red]Failed to decrypt data. The password may be incorrect or files are corrupt.[/]");
            return false;
        }

        return true;
    }

    private async Task<bool> InitializeNew()
    {
        var username = await PromptUsername();
        _password = await PromptNewPassword();

        // Generate and persist salt before deriving the key
        var salt = RandomNumberGenerator.GetBytes(16);
        await File.WriteAllBytesAsync(SaltPath, salt);

        // Generate RSA key pair
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var privateKey = rsa.ExportPkcs8PrivateKey();

        _userConfig = new UserConfig(username, publicKey, privateKey);

        var key = await DeriveAesKey();

        // identity.pub — plaintext SPKI DER (spec Section 8.3)
        await File.WriteAllBytesAsync(PublicKeyPath, publicKey);

        // identity.key — encrypted private key (spec Section 8.3)
        await _localFileService.WriteEncryptedBytes(PrivateKeyPath, privateKey, key);

        // config — encrypted username
        var configBytes = Encoding.UTF8.GetBytes(username);
        await _localFileService.WriteEncryptedBytes(ConfigPath, configBytes, key);

        AnsiConsole.MarkupLine($"[green]Initialized successfully. Your Peer ID is: {GetFingerprint()}[/]");
        return true;
    }

    private bool IsFullyInitialized() =>
        File.Exists(ConfigPath) && File.Exists(SaltPath) &&
        File.Exists(PrivateKeyPath) && File.Exists(PublicKeyPath);

    private bool IsPartiallyInitialized() =>
        File.Exists(ConfigPath) || File.Exists(SaltPath) ||
        File.Exists(PrivateKeyPath) || File.Exists(PublicKeyPath);

    private static async Task<string> PromptUsername()
    {
        return await AnsiConsole.PromptAsync(
            new TextPrompt<string>("Enter your username:")
                .Validate(name => string.IsNullOrWhiteSpace(name)
                    ? ValidationResult.Error("Username cannot be empty.")
                    : ValidationResult.Success()));
    }

    private static async Task<string> PromptExistingPassword()
    {
        return await AnsiConsole.PromptAsync(
            new TextPrompt<string>("Enter your password:")
                .PromptStyle("red")
                .Secret());
    }

    private static async Task<string> PromptNewPassword()
    {
        var password = await AnsiConsole.PromptAsync(
            new TextPrompt<string>("Choose a password to encrypt your data:")
                .PromptStyle("red")
                .Secret()
                .Validate(pass => string.IsNullOrWhiteSpace(pass)
                    ? ValidationResult.Error("Password cannot be empty.")
                    : ValidationResult.Success()));

        await AnsiConsole.PromptAsync(
            new TextPrompt<string>("Confirm your password:")
                .PromptStyle("red")
                .Secret()
                .Validate(pass => pass != password
                    ? ValidationResult.Error("Passwords do not match.")
                    : ValidationResult.Success()));

        return password;
    }
}