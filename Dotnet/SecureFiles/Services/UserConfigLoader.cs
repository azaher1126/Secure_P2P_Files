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

    public UserConfigLoader(LocalFileService localFileService)
    {
        _localFileService = localFileService;
    }

    /// <summary>
    /// Loads an existing config or runs first-time initialization.
    /// Returns a UserConfigProvider on success, or null if the user declined.
    /// </summary>
    public async Task<UserConfigProvider?> LoadOrInitialize()
    {
        AnsiConsole.Write(new FigletText("Secure P2P Files").Color(Color.Blue));
        AnsiConsole.WriteLine();

        if (IsFullyInitialized())
        {
            AnsiConsole.MarkupLine("[dim]Existing configuration found.[/]");
            return await LoadExisting();
        }

        if (IsPartiallyInitialized())
        {
            AnsiConsole.MarkupLine("[yellow]Warning:[/] Application data appears corrupt — some files are missing.");
            
            var reset = await AnsiConsole.ConfirmAsync(
                "Reset and reinitialize? [red]This will delete all existing data.[/]",
                defaultValue: false);

            if (!reset)
            {
                AnsiConsole.MarkupLine("[dim]Exiting without changes.[/]");
                return null;
            }

            AnsiConsole.MarkupLine("[dim]Clearing data directory...[/]");
            _localFileService.DeleteDataDirectory();
        }
        else
        {
            AnsiConsole.MarkupLine("[dim]No existing configuration found. Starting first-time setup.[/]");
        }

        AnsiConsole.WriteLine();
        _localFileService.EnsureDataDirectoryExists();
        return await InitializeNew();
    }

    private async Task<UserConfigProvider?> LoadExisting()
    {
        AnsiConsole.WriteLine();
        var password = await PromptExistingPassword();

        return await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Decrypting identity...", async _ =>
            {
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
                    var provider = new UserConfigProvider(config, password);

                    AnsiConsole.MarkupLine($"[green]Welcome back, {Markup.Escape(username)}![/]");
                    AnsiConsole.MarkupLine($"[dim]Peer ID: {provider.GetFingerprint()}[/]");

                    return provider;
                }
                catch
                {
                    AnsiConsole.MarkupLine("[red]Failed to decrypt data. The password may be incorrect or files are corrupt.[/]");
                    return null;
                }
            });
    }

    private async Task<UserConfigProvider> InitializeNew()
    {
        AnsiConsole.Write(new Rule("[bold]First-Time Setup[/]").LeftJustified());
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("This will create your identity and encrypt it with a password.");
        AnsiConsole.MarkupLine("[dim]Your data will be stored in:[/] " + Markup.Escape(_localFileService.DataDirectory));
        AnsiConsole.WriteLine();

        var username = await PromptUsername();
        var password = await PromptNewPassword();

        var provider = await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Setting up your identity...", async ctx =>
            {
                ctx.Status("Generating cryptographic salt...");
                var salt = RandomNumberGenerator.GetBytes(16);
                await _localFileService.WriteRawBytes(SaltFileName, salt);

                ctx.Status("Generating RSA-2048 key pair...");
                using var rsa = RSA.Create(2048);
                var publicKey = rsa.ExportSubjectPublicKeyInfo();
                var privateKey = rsa.ExportPkcs8PrivateKey();

                var config = new UserConfig(username, publicKey, privateKey);
                var provider = new UserConfigProvider(config, password);

                ctx.Status("Deriving encryption key (PBKDF2, 600k iterations)...");
                var key = await DeriveAesKey(password);

                ctx.Status("Saving public key...");
                await _localFileService.WriteRawBytes(PublicKeyFileName, publicKey);

                ctx.Status("Encrypting and saving private key...");
                await _localFileService.WriteEncryptedBytes(PrivateKeyFileName, privateKey, key);

                ctx.Status("Encrypting and saving config...");
                var configBytes = Encoding.UTF8.GetBytes(username);
                await _localFileService.WriteEncryptedBytes(ConfigFileName, configBytes, key);

                return provider;
            });

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[green]Setup Complete[/]").LeftJustified());
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"  [bold]Username:[/]  {Markup.Escape(username)}");
        AnsiConsole.MarkupLine($"  [bold]Peer ID:[/]   {provider.GetFingerprint()}");
        AnsiConsole.MarkupLine($"  [bold]Data dir:[/]  {Markup.Escape(_localFileService.DataDirectory)}");
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Press any key to continue...[/]");
        System.Console.ReadKey(true);

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
            new TextPrompt<string>("[bold]Choose a username[/] (this is your friendly name on the network):")
                .DefaultValue(Environment.UserName)
                .Validate(name => string.IsNullOrWhiteSpace(name)
                    ? ValidationResult.Error("Username cannot be empty.")
                    : ValidationResult.Success()));
    }

    private static async Task<string> PromptExistingPassword()
    {
        return await AnsiConsole.PromptAsync(
            new TextPrompt<string>("Enter your [bold]password[/] to unlock:")
                .PromptStyle("red")
                .Secret());
    }

    private static async Task<string> PromptNewPassword()
    {
        AnsiConsole.MarkupLine("[dim]Your password encrypts your private key and all stored files locally.[/]");
        AnsiConsole.WriteLine();

        var password = await AnsiConsole.PromptAsync(
            new TextPrompt<string>("[bold]Choose a password:[/]")
                .PromptStyle("red")
                .Secret()
                .Validate(pass => string.IsNullOrWhiteSpace(pass)
                    ? ValidationResult.Error("Password cannot be empty.")
                    : ValidationResult.Success()));

        await AnsiConsole.PromptAsync(
            new TextPrompt<string>("[bold]Confirm password:[/]")
                .PromptStyle("red")
                .Secret()
                .Validate(pass => pass != password
                    ? ValidationResult.Error("Passwords do not match.")
                    : ValidationResult.Success()));

        return password;
    }
}
