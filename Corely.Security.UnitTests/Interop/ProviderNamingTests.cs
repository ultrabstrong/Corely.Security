using System.Security.Cryptography;
using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.KeyStore;
using Corely.Security.Encryption.Providers;
using Corely.Security.Signature;
using Corely.Security.Signature.Factories;
using Corely.Security.Signature.Providers;

namespace Corely.Security.UnitTests.Interop;

// ProviderName is the factory lookup key everywhere, and for encryption providers it is also the
// prefix written into stored values. The default-configuration names must therefore stay byte for
// byte what they have always been; the configured-value names exist so a provider stops reporting
// settings it is not using.
public class ProviderNamingTests
{
    [Fact]
    public void DefaultNames_MatchTheirConstants()
    {
        Assert.Equal(
            AsymmetricSignatureConstants.ECDSA_SHA256_CODE,
            new ECDsaSignatureProvider(HashAlgorithmName.SHA256).ProviderName
        );
        Assert.Equal(
            AsymmetricSignatureConstants.RSA_SHA256_CODE,
            new RsaSignatureProvider(HashAlgorithmName.SHA256).ProviderName
        );
        Assert.Equal(
            AsymmetricEncryptionConstants.RSA_CODE,
            new RsaEncryptionProvider(RSAEncryptionPadding.OaepSHA256).ProviderName
        );
    }

    [Theory]
    [InlineData("SHA384", "ECDSA-SHA384")]
    [InlineData("SHA512", "ECDSA-SHA512")]
    public void Ecdsa_NameReflectsTheConfiguredHash(string hash, string expected)
    {
        Assert.Equal(expected, new ECDsaSignatureProvider(new HashAlgorithmName(hash)).ProviderName);
    }

    [Theory]
    [InlineData("SHA384", "RSA-PKCS1-SHA384")]
    [InlineData("SHA512", "RSA-PKCS1-SHA512")]
    public void RsaSignature_NameReflectsTheConfiguredHash(string hash, string expected)
    {
        Assert.Equal(expected, new RsaSignatureProvider(new HashAlgorithmName(hash)).ProviderName);
    }

    [Fact]
    public void RsaEncryption_NameReflectsTheConfiguredPadding()
    {
        Assert.Equal(
            "RSA-PKCS1",
            new RsaEncryptionProvider(RSAEncryptionPadding.Pkcs1).ProviderName
        );
        Assert.Equal(
            "RSA-OAEP-SHA512",
            new RsaEncryptionProvider(RSAEncryptionPadding.OaepSHA512).ProviderName
        );
    }

    // Key size and curve come from whichever key the key store supplies, so a provider cannot
    // report them honestly and no longer claims to.
    [Fact]
    public void NamesDoNotClaimKeyProperties()
    {
        string[] names =
        [
            new ECDsaSignatureProvider(HashAlgorithmName.SHA256).ProviderName,
            new RsaSignatureProvider(HashAlgorithmName.SHA256).ProviderName,
            new RsaEncryptionProvider(RSAEncryptionPadding.OaepSHA256).ProviderName,
        ];

        Assert.All(names, n => Assert.DoesNotContain("2048", n));
        Assert.All(names, n => Assert.DoesNotContain("P256", n));
    }

    // The 1.x names are the prefix on values encrypted by 1.x, so they must still resolve.
    [Fact]
    public void TheFactoryStillResolvesLegacyNames()
    {
        var encryption = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);

        Assert.Same(
            encryption.GetProvider(AsymmetricEncryptionConstants.RSA_CODE),
            encryption.GetProvider(AsymmetricEncryptionConstants.LEGACY_RSA_CODE)
        );

        var signature = new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE);

        Assert.Same(
            signature.GetProvider(AsymmetricSignatureConstants.ECDSA_SHA256_CODE),
            signature.GetProvider(AsymmetricSignatureConstants.LEGACY_ECDSA_SHA256_CODE)
        );
        Assert.Same(
            signature.GetProvider(AsymmetricSignatureConstants.RSA_SHA256_CODE),
            signature.GetProvider(AsymmetricSignatureConstants.LEGACY_RSA_SHA256_CODE)
        );
    }

    // A value written by 1.x carries the old prefix and must round-trip through the factory.
    [Fact]
    public void AValueEncryptedUnderTheLegacyNameStillDecrypts()
    {
        var factory = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);
        var provider = factory.GetDefaultProvider();
        var (pub, priv) = provider.GetAsymmetricKeyProvider().CreateKeys();
        var keyStore = new InMemoryAsymmetricKeyStoreProvider(pub, priv);

        var written = provider.Encrypt("legacy payload", keyStore);
        var legacy =
            $"{AsymmetricEncryptionConstants.LEGACY_RSA_CODE}:{string.Join(':', written.Split(':')[1..])}";

        var resolved = factory.GetProviderForDecrypting(legacy);

        Assert.Equal("legacy payload", resolved.Decrypt(legacy, keyStore));
    }
}
