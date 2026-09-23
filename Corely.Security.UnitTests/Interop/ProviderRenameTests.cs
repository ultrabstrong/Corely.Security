using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.Interop;

public class ProviderRenameTests
{
    private const string LegacyName = "AES-256-GCM-LEGACY";
    private const string Plaintext = "value written before the rename";

    private static InMemorySymmetricKeyStoreProvider KeyStore() =>
        new(new AesKeyProvider().CreateKey());

    private static string RewritePrefix(string value, string name) =>
        $"{name}:{string.Join(':', value.Split(':')[1..])}";

    [Fact]
    public void AProviderReadsValuesWrittenUnderAnEarlierName()
    {
        var keyStore = KeyStore();
        var provider = new AesGcmEncryptionProvider();

        var underLegacyName = RewritePrefix(provider.Encrypt(Plaintext, keyStore), LegacyName);

        Assert.NotEqual(provider.ProviderName, LegacyName);
        Assert.Equal(Plaintext, provider.Decrypt(underLegacyName, keyStore));
    }

    [Fact]
    public void TheFactoryRoutesALegacyNameToTheProviderRegisteredUnderIt()
    {
        var provider = new AesGcmEncryptionProvider();
        var factory = new SymmetricEncryptionProviderFactory(provider.ProviderName);
        factory.AddProvider(LegacyName, provider);

        var keyStore = KeyStore();
        var underLegacyName = RewritePrefix(provider.Encrypt(Plaintext, keyStore), LegacyName);

        var resolved = factory.GetProviderForDecrypting(underLegacyName);

        Assert.Same(provider, resolved);
        Assert.Equal(Plaintext, resolved.Decrypt(underLegacyName, keyStore));
    }

    [Fact]
    public void NewValuesAreWrittenUnderTheCurrentName()
    {
        var provider = new AesGcmEncryptionProvider();

        var written = provider.Encrypt(Plaintext, KeyStore());

        Assert.StartsWith($"{SymmetricEncryptionConstants.AES_GCM_CODE}:", written);
    }

    [Theory]
    [InlineData(":1:abc")]
    [InlineData("   :1:abc")]
    [InlineData("name:notanumber:abc")]
    [InlineData("name:1:")]
    [InlineData("name:1")]
    public void AMalformedValueIsStillRejected(string value)
    {
        Assert.Throws<EncryptionException>(() =>
            new AesGcmEncryptionProvider().Decrypt(value, KeyStore())
        );
    }
}
