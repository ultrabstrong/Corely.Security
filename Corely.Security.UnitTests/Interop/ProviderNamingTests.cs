using System.Security.Cryptography;
using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.Encryption.Providers;
using Corely.Security.KeyStore;
using Corely.Security.Signature;
using Corely.Security.Signature.Factories;
using Corely.Security.Signature.Providers;

namespace Corely.Security.UnitTests.Interop;

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
        Assert.Equal(
            expected,
            new ECDsaSignatureProvider(new HashAlgorithmName(hash)).ProviderName
        );
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

    [Fact]
    public void TheFactoryStillResolvesLegacyNames()
    {
        var encryption = new AsymmetricEncryptionProviderFactory(
            AsymmetricEncryptionConstants.RSA_CODE
        );

        Assert.Same(
            encryption.GetProvider(AsymmetricEncryptionConstants.RSA_CODE),
            encryption.GetProvider(AsymmetricEncryptionConstants.LEGACY_RSA_CODE)
        );

        var signature = new AsymmetricSignatureProviderFactory(
            AsymmetricSignatureConstants.ECDSA_SHA256_CODE
        );

        Assert.Same(
            signature.GetProvider(AsymmetricSignatureConstants.ECDSA_SHA256_CODE),
            signature.GetProvider(AsymmetricSignatureConstants.LEGACY_ECDSA_SHA256_CODE)
        );
        Assert.Same(
            signature.GetProvider(AsymmetricSignatureConstants.RSA_SHA256_CODE),
            signature.GetProvider(AsymmetricSignatureConstants.LEGACY_RSA_SHA256_CODE)
        );
    }

    [Fact]
    public void AValueEncryptedUnderTheLegacyNameStillDecrypts()
    {
        var factory = new AsymmetricEncryptionProviderFactory(
            AsymmetricEncryptionConstants.RSA_CODE
        );
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
