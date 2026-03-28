namespace SecureFiles.Networking;

public enum MessageType : byte
{
    GetFileList = 0x02,
    FileListResponse = 0x03,
    ReqToReceive = 0x04,
    ReqToSend = 0x05,
    KeyMigration = 0x06,
    ConsentResponse = 0x07,
    DataTransfer = 0x08
}
