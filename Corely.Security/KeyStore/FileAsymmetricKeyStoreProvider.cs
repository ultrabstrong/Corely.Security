using System.Buffers;
using System.Buffers.Text;
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

    // Read as bytes and decode in place. Going through File.ReadAllText would put the private key
    // into a string, which cannot be zeroed and lives until the GC happens to collect it.
    private (byte[] PublicKey, byte[] PrivateKey) ReadKeys()
    {
        var fileBytes = GetFileBytes();

        try
        {
            var lines = SplitLines(fileBytes);
            if (lines.Count < 2)
            {
                throw new KeyStoreException(
                    "Key file must contain a public key and a private key on separate lines."
                )
                {
                    Reason = KeyStoreException.ErrorReason.CurrentKeyNotFound,
                };
            }

            return (Decode(fileBytes, lines[0]), Decode(fileBytes, lines[1]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    private static List<(int Start, int Length)> SplitLines(byte[] bytes)
    {
        List<(int, int)> lines = [];
        var start = 0;
        for (var i = 0; i <= bytes.Length; i++)
        {
            if (i == bytes.Length || bytes[i] == (byte)'\n')
            {
                var end = i;
                if (end > start && bytes[end - 1] == (byte)'\r')
                    end--;
                if (end > start)
                    lines.Add((start, end - start));
                start = i + 1;
            }
        }
        return lines;
    }

    private static byte[] Decode(byte[] source, (int Start, int Length) line)
    {
        var span = source.AsSpan(line.Start, line.Length);
        var decoded = new byte[Base64.GetMaxDecodedFromUtf8Length(span.Length)];

        var status = Base64.DecodeFromUtf8(span, decoded, out _, out var written);
        if (status != OperationStatus.Done)
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

    protected virtual byte[] GetFileBytes() => File.ReadAllBytes(_filePath);
}
