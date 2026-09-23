using System.Security.Cryptography;

namespace Corely.Security.KeyStore;

public class InMemorySymmetricKeyStoreProvider : ISymmetricKeyStoreProvider
{
    private readonly Dictionary<int, byte[]> _keys = [];
    private int _version = 0;

    public InMemorySymmetricKeyStoreProvider(ReadOnlySpan<byte> key)
    {
        Add(key);
    }

    public InMemorySymmetricKeyStoreProvider(string base64Key)
        : this(Convert.FromBase64String(base64Key)) { }

    public void Add(ReadOnlySpan<byte> key)
    {
        _keys.Add(++_version, key.ToArray());
    }

    public void Add(string base64Key) => Add(Convert.FromBase64String(base64Key));

    public int GetCurrentVersion() => _version;

    public byte[] Get(int version)
    {
        if (!_keys.TryGetValue(version, out var key))
        {
            throw new KeyStoreException($"Key version {version} is invalid")
            {
                Reason = KeyStoreException.ErrorReason.InvalidVersion,
            };
        }

        return [.. key];
    }

    public byte[] GetCurrentKey() => [.. _keys[_version]];

    public void Clear()
    {
        foreach (var key in _keys.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }
        _keys.Clear();
    }
}
