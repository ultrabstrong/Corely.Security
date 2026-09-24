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

    // Bytes, not ReadAllText: a string key can't be zeroed.
    public byte[] GetCurrentKey()
    {
        var fileBytes = GetFileBytes();

        try
        {
            return fileBytes.WithoutSurroundingWhitespace().DecodedBase64Key();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    protected virtual byte[] GetFileBytes() => File.ReadAllBytes(_filePath);
}
