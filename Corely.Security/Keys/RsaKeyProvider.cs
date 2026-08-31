using System.Security.Cryptography;

namespace Corely.Security.Keys;

internal sealed class RsaKeyProvider : IAsymmetricKeyProvider
{
    public const int DEFAULT_KEY_SIZE = 2048;

    private readonly int _keySize;

    public RsaKeyProvider(int keySize = DEFAULT_KEY_SIZE)
    {
        if (keySize < 0 || keySize % 8 != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(keySize),
                "Key size must be a positive multiple of 8."
            );
        }
        _keySize = keySize;
    }

    public (byte[] PublicKey, byte[] PrivateKey) CreateKeys()
    {
        using var rsa = RSA.Create(_keySize);
        return (rsa.ExportSubjectPublicKeyInfo(), rsa.ExportPkcs8PrivateKey());
    }

    public bool IsKeyValid(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        try
        {
            using var rsa = RSA.Create();

            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            if (!rsa.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(publicKey))
            {
                return false;
            }

            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            return rsa.ExportPkcs8PrivateKey().AsSpan().SequenceEqual(privateKey);
        }
        catch
        {
            return false;
        }
    }
}
