using System.Security.Cryptography;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.KeyStore;

public class InMemorySymmetricKeyStoreProviderTests
{
    private static byte[] Key() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void GetCurrentKey_ReturnsKey()
    {
        var key = Key();
        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(key);

        Assert.Equal(key, keyStoreProvider.GetCurrentKey());
    }

    // The store must hand out copies; a caller zeroing what it received would otherwise wipe the
    // stored key, since the provider bases zero every key they are given.
    [Fact]
    public void GetCurrentKey_ReturnsACopyTheCallerMayZero()
    {
        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(Key());

        var first = keyStoreProvider.GetCurrentKey();
        CryptographicOperations.ZeroMemory(first);

        Assert.NotEqual(first, keyStoreProvider.GetCurrentKey());
    }

    [Fact]
    public void Constructor_AcceptsABase64Key()
    {
        var key = Key();

        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(Convert.ToBase64String(key));

        Assert.Equal(key, keyStoreProvider.GetCurrentKey());
    }

    [Fact]
    public void GetCurrentVersion_ReturnsOne()
    {
        Assert.Equal(1, new InMemorySymmetricKeyStoreProvider(Key()).GetCurrentVersion());
    }

    [Fact]
    public void Add_IncrementsVersion()
    {
        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(Key());

        keyStoreProvider.Add(Key());

        Assert.Equal(2, keyStoreProvider.GetCurrentVersion());
    }

    [Fact]
    public void Get_ReturnsKey()
    {
        var first = Key();
        var second = Key();
        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(first);
        keyStoreProvider.Add(second);

        Assert.Equal(first, keyStoreProvider.Get(1));
        Assert.Equal(second, keyStoreProvider.Get(2));
    }

    [Fact]
    public void Get_Throws_WhenVersionIsInvalid()
    {
        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(Key());

        var ex = Record.Exception(() => keyStoreProvider.Get(2));

        Assert.NotNull(ex);
        Assert.IsType<KeyStoreException>(ex);
        Assert.Equal(KeyStoreException.ErrorReason.InvalidVersion, ((KeyStoreException)ex).Reason);
    }

    // Clear drops the keys but deliberately leaves the version counter alone: a new key reusing
    // version 1 would silently mismatch values already written under the old version 1.
    [Fact]
    public void Clear_DiscardsStoredKeys()
    {
        var keyStoreProvider = new InMemorySymmetricKeyStoreProvider(Key());

        keyStoreProvider.Clear();

        Assert.Equal(1, keyStoreProvider.GetCurrentVersion());
        Assert.Throws<KeyStoreException>(() => keyStoreProvider.Get(1));
    }
}
