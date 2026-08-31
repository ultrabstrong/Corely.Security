using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.Encryption.Providers;

/// <summary>
/// A ciphertext shorter than the IV previously produced a negative array length rather than a
/// clean failure.
/// </summary>
public class AesEncryptionProviderRobustnessTests
{
    private readonly AesEncryptionProvider _provider = new();

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    public void Decrypt_ThrowsEncryptionException_WhenPayloadIsShorterThanTheIv(int payloadSize)
    {
        var keyStore = CreateKeyStore();
        var truncated =
            $"{_provider.ProviderName}:1:{Convert.ToBase64String(new byte[payloadSize])}";

        var ex = Record.Exception(() => _provider.Decrypt(truncated, keyStore));

        Assert.NotNull(ex);
        Assert.IsType<EncryptionException>(ex);
    }

    [Fact]
    public void RoundTrip_StillWorks()
    {
        var keyStore = CreateKeyStore();

        var encrypted = _provider.Encrypt("value", keyStore);

        Assert.Equal("value", _provider.Decrypt(encrypted, keyStore));
    }

    private static ISymmetricKeyStoreProvider CreateKeyStore() =>
        new InMemorySymmetricKeyStoreProvider(new AesKeyProvider().CreateKey());
}
