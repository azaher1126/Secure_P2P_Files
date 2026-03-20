namespace SecureFiles.Helpers;

public static class BinaryHelper
{
    public static void WriteLengthPrefixedBytes(this BinaryWriter writer, byte[] bytes)
    {
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
    
    public static byte[] ReadLengthPrefixedBytes(this BinaryReader reader)
    {
        var length = reader.ReadInt32();
        return reader.ReadBytes(length);
    }
}