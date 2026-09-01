using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.KeyStore;

public class InMemoryAsymmetricKeyStoreProviderTests
{
    private static (byte[] PublicKey, byte[] PrivateKey) Keys() =>
        new EcdsaKeyProvider().CreateKeys();

    [Fact]
    public void GetCurrentKeys_ReturnsKeys()
    {
        var (pub, priv) = Keys();
        var keyStoreProvider = new InMemoryAsymmetricKeyStoreProvider(pub, priv);

        var (actualPublic, actualPrivate) = keyStoreProvider.GetCurrentKeys();

        Assert.Equal(pub, actualPublic);
        Assert.Equal(priv, actualPrivate);
    }

    [Fact]
    public void Constructor_AcceptsBase64Keys()
    {
        var (pub, priv) = Keys();

        var keyStoreProvider = new InMemoryAsymmetricKeyStoreProvider(
            Convert.ToBase64String(pub),
            Convert.ToBase64String(priv)
        );

        var (actualPublic, actualPrivate) = keyStoreProvider.GetCurrentKeys();
        Assert.Equal(pub, actualPublic);
        Assert.Equal(priv, actualPrivate);
    }

    [Fact]
    public void GetCurrentVersion_ReturnsOne()
    {
        var (pub, priv) = Keys();
        Assert.Equal(1, new InMemoryAsymmetricKeyStoreProvider(pub, priv).GetCurrentVersion());
    }

    [Fact]
    public void Add_IncrementsVersion()
    {
        var (pub, priv) = Keys();
        var keyStoreProvider = new InMemoryAsymmetricKeyStoreProvider(pub, priv);

        var (nextPublic, nextPrivate) = Keys();
        keyStoreProvider.Add(nextPublic, nextPrivate);

        Assert.Equal(2, keyStoreProvider.GetCurrentVersion());
    }

    [Fact]
    public void Get_ReturnsKey()
    {
        var (firstPublic, firstPrivate) = Keys();
        var (secondPublic, secondPrivate) = Keys();
        var keyStoreProvider = new InMemoryAsymmetricKeyStoreProvider(firstPublic, firstPrivate);
        keyStoreProvider.Add(secondPublic, secondPrivate);

        Assert.Equal(firstPublic, keyStoreProvider.Get(1).PublicKey);
        Assert.Equal(firstPrivate, keyStoreProvider.Get(1).PrivateKey);
        Assert.Equal(secondPublic, keyStoreProvider.Get(2).PublicKey);
        Assert.Equal(secondPrivate, keyStoreProvider.Get(2).PrivateKey);
    }

    [Fact]
    public void Get_Throws_WhenVersionIsInvalid()
    {
        var (pub, priv) = Keys();
        var keyStoreProvider = new InMemoryAsymmetricKeyStoreProvider(pub, priv);

        var ex = Record.Exception(() => keyStoreProvider.Get(2));

        Assert.NotNull(ex);
        Assert.IsType<KeyStoreException>(ex);
        Assert.Equal(KeyStoreException.ErrorReason.InvalidVersion, ((KeyStoreException)ex).Reason);
    }
}
