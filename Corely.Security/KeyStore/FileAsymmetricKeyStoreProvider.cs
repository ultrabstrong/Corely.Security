using System.Security.Cryptography;

namespace Corely.Security.KeyStore;

public class FileAsymmetricKeyStoreProvider : IAsymmetricKeyStoreProvider
{
    private const int ONLY_VERSION = 1;

    private readonly string _filePath;

    public FileAsymmetricKeyStoreProvider(string filePath)
    {
        _filePath = filePath;
    }

    public int GetCurrentVersion() => ONLY_VERSION;

    public (byte[] PublicKey, byte[] PrivateKey) Get(int version)
    {
        if (version != ONLY_VERSION)
        {
            throw new KeyStoreException(
                $"Key version {version} is invalid. {nameof(FileAsymmetricKeyStoreProvider)} holds "
                    + $"a single key pair at version {ONLY_VERSION} and does not support rotation."
            )
            {
                Reason = KeyStoreException.ErrorReason.InvalidVersion,
            };
        }

        return ReadKeys();
    }

    public (byte[] PublicKey, byte[] PrivateKey) GetCurrentKeys() => ReadKeys();

    // Bytes, not ReadAllText: a string key can't be zeroed.
    private (byte[] PublicKey, byte[] PrivateKey) ReadKeys()
    {
        var fileBytes = GetFileBytes();

        try
        {
            var lines = fileBytes.NonEmptyLineRanges();
            if (lines.Count < 2)
            {
                throw new KeyStoreException(
                    "Key file must contain a public key and a private key on separate lines."
                )
                {
                    Reason = KeyStoreException.ErrorReason.CurrentKeyNotFound,
                };
            }

            return (
                fileBytes.AsSpan(lines[0].Start, lines[0].Length).DecodedBase64Key(),
                fileBytes.AsSpan(lines[1].Start, lines[1].Length).DecodedBase64Key()
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    protected virtual byte[] GetFileBytes() => File.ReadAllBytes(_filePath);
}
