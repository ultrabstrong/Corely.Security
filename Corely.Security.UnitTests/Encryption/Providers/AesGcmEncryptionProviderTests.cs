using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.Encryption.Providers;

public class AesGcmEncryptionProviderTests : SymmetricEncryptionProviderGenericTests
{
    private readonly AesGcmEncryptionProvider _provider = new();

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(SymmetricEncryptionConstants.AES_GCM_CODE, _provider.ProviderName);
    }

    [Fact]
    public void ProviderDescription_ReturnsNonDefaultValue()
    {
        var description = _provider.ProviderDescription;

        Assert.False(string.IsNullOrWhiteSpace(description));
        Assert.NotEqual(_provider.GetType().Name, description);
    }

    [Fact]
    public override void GetSymmetricKeyProvider_ReturnsCorrectKeyProvider_ForImplementation()
    {
        var keyProvider = _provider.GetSymmetricKeyProvider();

        Assert.NotNull(keyProvider);
        Assert.IsType<AesKeyProvider>(keyProvider);
    }

    public override ISymmetricEncryptionProvider GetEncryptionProvider() =>
        new AesGcmEncryptionProvider();

    [Fact]
    public void Decrypt_Throws_WhenCiphertextIsTampered()
    {
        var keyStore = CreateKeyStore();
        var encrypted = _provider.Encrypt("sensitive value", keyStore);

        var tampered = FlipALastPayloadCharacter(encrypted);

        Assert.ThrowsAny<Exception>(() => _provider.Decrypt(tampered, keyStore));
    }

    [Fact]
    public void Decrypt_Throws_WhenAuthenticationTagIsTampered()
    {
        var keyStore = CreateKeyStore();
        var encrypted = _provider.Encrypt("sensitive value", keyStore);

        var parts = encrypted.Split(':');
        var payload = Convert.FromBase64String(parts[2]);
        payload[12] ^= 0xFF;
        var tampered = $"{parts[0]}:{parts[1]}:{Convert.ToBase64String(payload)}";

        Assert.ThrowsAny<Exception>(() => _provider.Decrypt(tampered, keyStore));
    }

    [Fact]
    public void Encrypt_ProducesDifferentCiphertext_ForTheSamePlaintext()
    {
        var keyStore = CreateKeyStore();

        var first = _provider.Encrypt("same value", keyStore);
        var second = _provider.Encrypt("same value", keyStore);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Decrypt_Throws_WhenPayloadIsTooShortForNonceAndTag()
    {
        var keyStore = CreateKeyStore();
        var truncated = $"{_provider.ProviderName}:1:{Convert.ToBase64String(new byte[8])}";

        var ex = Record.Exception(() => _provider.Decrypt(truncated, keyStore));

        Assert.NotNull(ex);
        Assert.IsType<EncryptionException>(ex);
    }

    private static ISymmetricKeyStoreProvider CreateKeyStore() =>
        new InMemorySymmetricKeyStoreProvider(new AesKeyProvider().CreateKey());

    private static string FlipALastPayloadCharacter(string encrypted)
    {
        var parts = encrypted.Split(':');
        var payload = Convert.FromBase64String(parts[2]);
        payload[^1] ^= 0xFF;
        return $"{parts[0]}:{parts[1]}:{Convert.ToBase64String(payload)}";
    }
}
