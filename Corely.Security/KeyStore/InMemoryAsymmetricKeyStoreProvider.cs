using System.Security.Cryptography;

namespace Corely.Security.KeyStore;

public class InMemoryAsymmetricKeyStoreProvider : IAsymmetricKeyStoreProvider
{
    private readonly Dictionary<int, (byte[] PublicKey, byte[] PrivateKey)> _keys = [];
    private int _version = 0;

    public InMemoryAsymmetricKeyStoreProvider(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> privateKey
    )
    {
        Add(publicKey, privateKey);
    }

    public InMemoryAsymmetricKeyStoreProvider(string base64PublicKey, string base64PrivateKey)
        : this(
            Convert.FromBase64String(base64PublicKey),
            Convert.FromBase64String(base64PrivateKey)
        ) { }

    public void Add(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        _keys.Add(++_version, (publicKey.ToArray(), privateKey.ToArray()));
    }

    public void Add(string base64PublicKey, string base64PrivateKey) =>
        Add(Convert.FromBase64String(base64PublicKey), Convert.FromBase64String(base64PrivateKey));

    public int GetCurrentVersion() => _version;

    public (byte[] PublicKey, byte[] PrivateKey) Get(int version)
    {
        if (!_keys.TryGetValue(version, out var keys))
        {
            throw new KeyStoreException($"Key version {version} is invalid")
            {
                Reason = KeyStoreException.ErrorReason.InvalidVersion,
            };
        }

        return ([.. keys.PublicKey], [.. keys.PrivateKey]);
    }

    public (byte[] PublicKey, byte[] PrivateKey) GetCurrentKeys()
    {
        var keys = _keys[_version];
        return ([.. keys.PublicKey], [.. keys.PrivateKey]);
    }

    public void Clear()
    {
        foreach (var (_, privateKey) in _keys.Values)
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
        _keys.Clear();
    }
}
