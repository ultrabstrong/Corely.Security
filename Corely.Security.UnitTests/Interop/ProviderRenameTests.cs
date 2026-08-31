using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.Encryption.Providers;
using Corely.Security.KeyStore;
using Corely.Security.Keys;

namespace Corely.Security.UnitTests.Interop;

// A provider name is written into every value it encrypts, so a name can only ever change if
// providers can still read values carrying the old one. Decrypt deliberately does not check the
// stored prefix against its own ProviderName: the factory already routed the value here by that
// prefix, and re-checking it would make every shipped name permanent.
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

    // Reading under an alias must not change what new writes are labelled.
    [Fact]
    public void NewValuesAreWrittenUnderTheCurrentName()
    {
        var provider = new AesGcmEncryptionProvider();

        var written = provider.Encrypt(Plaintext, KeyStore());

        Assert.StartsWith($"{SymmetricEncryptionConstants.AES_GCM_CODE}:", written);
    }

    // Dropping the identity check must not weaken shape validation.
    [Theory]
    [InlineData(":1:abc")]
    [InlineData("   :1:abc")]
    [InlineData("name:notanumber:abc")]
    [InlineData("name:1:")]
    [InlineData("name:1")]
    public void AMalformedValueIsStillRejected(string value)
    {
        Assert.Throws<EncryptionException>(
            () => new AesGcmEncryptionProvider().Decrypt(value, KeyStore())
        );
    }
}
