using System.Buffers.Text;
using System.Security.Cryptography;

namespace Corely.Security.KeyStore;

public class FileSymmetricKeyStoreProvider : ISymmetricKeyStoreProvider
{
    private const int ONLY_VERSION = 1;

    private readonly string _filePath;

    public FileSymmetricKeyStoreProvider(string filePath)
    {
        _filePath = filePath;
    }

    public int GetCurrentVersion() => ONLY_VERSION;

    public byte[] Get(int version)
    {
        if (version != ONLY_VERSION)
        {
            throw new KeyStoreException(
                $"Key version {version} is invalid. {nameof(FileSymmetricKeyStoreProvider)} holds "
                    + $"a single key at version {ONLY_VERSION} and does not support rotation."
            )
            {
                Reason = KeyStoreException.ErrorReason.InvalidVersion,
            };
        }

        return GetCurrentKey();
    }

    // Read as bytes and decode in place. Going through File.ReadAllText would put the key into a
    // string, which cannot be zeroed and lives until the GC happens to collect it.
    public byte[] GetCurrentKey()
    {
        var fileBytes = GetFileBytes();

        try
        {
            var trimmed = TrimWhitespace(fileBytes);
            var decoded = new byte[Base64.GetMaxDecodedFromUtf8Length(trimmed.Length)];

            var status = Base64.DecodeFromUtf8(trimmed, decoded, out _, out var written);
            if (status != System.Buffers.OperationStatus.Done)
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw new KeyStoreException("Key file does not contain valid Base64.")
                {
                    Reason = KeyStoreException.ErrorReason.CurrentKeyNotFound,
                };
            }

            var key = decoded[..written];
            if (written != decoded.Length)
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    private static ReadOnlySpan<byte> TrimWhitespace(byte[] bytes)
    {
        int start = 0,
            end = bytes.Length;
        while (start < end && IsWhitespace(bytes[start]))
            start++;
        while (end > start && IsWhitespace(bytes[end - 1]))
            end--;
        return bytes.AsSpan(start, end - start);
    }

    private static bool IsWhitespace(byte b) => b is 0x20 or 0x09 or 0x0A or 0x0D;

    protected virtual byte[] GetFileBytes() => File.ReadAllBytes(_filePath);
}
