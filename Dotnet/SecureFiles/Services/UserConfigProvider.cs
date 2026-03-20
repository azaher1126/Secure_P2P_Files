using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class UserConfigProvider
{
    private const string SaltFileName = "local.salt";

    private readonly UserConfig _userConfig;
    private readonly string _password;

    public string Username => _userConfig.Username;
    public byte[] PublicKey => _userConfig.PublicKey;
    public byte[] PrivateKey => _userConfig.PrivateKey;

    public UserConfigProvider(UserConfig userConfig, string password)
    {
        _userConfig = userConfig;
        _password = password;
    }

    public string GetFingerprint()
    {
        var hash = SHA256.HashData(PublicKey);
        return Convert.ToHexStringLower(hash[..8]);
    }

    public async Task<byte[]> DeriveAesKey(LocalFileService localFileService, CancellationToken cancellationToken = default)
    {
        var salt = await localFileService.ReadRawBytes(SaltFileName, cancellationToken);
        return Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(_password),
            salt: salt,
            iterations: 600_000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 32);
    }
}
