namespace SecureFiles.Models;

public record UserConfig(string Username, byte[] PublicKey, byte[] PrivateKey);