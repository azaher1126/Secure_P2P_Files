using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;
using Spectre.Console;

namespace SecureFiles.Services;

public class UserConfigLoader
{
    private const string ConfigFileName = "config";
    private const string SaltFileName = "local.salt";
    private const string PrivateKeyFileName = "identity.key";
    private const string PublicKeyFileName = "identity.pub";

    private readonly LocalFileService _localFileService;
    private readonly string? _password;

    public UserConfigLoader(LocalFileService localFileService, string? password = null)
    {
        _localFileService = localFileService;
        _password = password;
    }

    /// <summary>
    /// Loads an existing config or runs first-time initialization.
    /// Returns a UserConfigProvider on success, or null if the user declined.
    /// </summary>
    public async Task<UserConfigProvider?> LoadOrInitialize()
    {
        if (IsFullyInitialized())
            return await LoadExisting();

        if (IsPartiallyInitialized())
        {
            var reset = await AnsiConsole.ConfirmAsync(
                "Application data appears corrupt (some files are missing). Reset and reinitialize? This will delete all existing data.",
                defaultValue: false);

            if (!reset) return null;

            _localFileService.DeleteDataDirectory();
        }

        _localFileService.EnsureDataDirectoryExists();
        return await InitializeNew();
    }

    private async Task<UserConfigProvider?> LoadExisting()
    {
        var password = _password ?? await PromptExistingPassword();

        byte[] key;
        try
        {
            key = await DeriveAesKey(password);
        }
        catch
        {
            AnsiConsole.MarkupLine("[red]Failed to derive encryption key. The salt file may be corrupt.[/]");
            return null;
        }

        try
        {
            var publicKey = await _localFileService.ReadRawBytes(PublicKeyFileName);
            var privateKey = await _localFileService.ReadEncryptedBytes(PrivateKeyFileName, key);
            var usernameBytes = await _localFileService.ReadEncryptedBytes(ConfigFileName, key);
            var username = Encoding.UTF8.GetString(usernameBytes);

            var config = new UserConfig(username, publicKey, privateKey);
            return new UserConfigProvider(config, password);
        }
        catch
        {
            AnsiConsole.MarkupLine("[red]Failed to decrypt data. The password may be incorrect or files are corrupt.[/]");
            return null;
        }
    }

    private async Task<UserConfigProvider> InitializeNew()
    {
        var username = await PromptUsername();
        var password = _password ?? await PromptNewPassword();

        var salt = RandomNumberGenerator.GetBytes(16);
        await _localFileService.WriteRawBytes(SaltFileName, salt);

        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var privateKey = rsa.ExportPkcs8PrivateKey();

        var config = new UserConfig(username, publicKey, privateKey);
        var provider = new UserConfigProvider(config, password);

        var key = await DeriveAesKey(password);

        await _localFileService.WriteRawBytes(PublicKeyFileName, publicKey);
        await _localFileService.WriteEncryptedBytes(PrivateKeyFileName, privateKey, key);

        var configBytes = Encoding.UTF8.GetBytes(username);
        await _localFileService.WriteEncryptedBytes(ConfigFileName, configBytes, key);

        AnsiConsole.MarkupLine($"[green]Initialized successfully. Your Peer ID is: {provider.GetFingerprint()}[/]");
        return provider;
    }

    private async Task<byte[]> DeriveAesKey(string password)
    {
        var salt = await _localFileService.ReadRawBytes(SaltFileName);
        return Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(password),
            salt: salt,
            iterations: 600_000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 32);
    }

    private bool IsFullyInitialized() =>
        _localFileService.FileExists(ConfigFileName) && _localFileService.FileExists(SaltFileName) &&
        _localFileService.FileExists(PrivateKeyFileName) && _localFileService.FileExists(PublicKeyFileName);

    private bool IsPartiallyInitialized() =>
        _localFileService.FileExists(ConfigFileName) || _localFileService.FileExists(SaltFileName) ||
        _localFileService.FileExists(PrivateKeyFileName) || _localFileService.FileExists(PublicKeyFileName);

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
