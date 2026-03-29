namespace SecureFiles.Models;

public record Contact(string Fingerprint, byte[] PublicKeyDer, List<SharedFile> CachedFiles);
