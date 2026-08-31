using System.Security.Cryptography;
using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Signature;
using Corely.Security.Signature.Providers;

namespace Corely.Security.UnitTests.Interop;

// ProviderName is the factory lookup key everywhere, and for encryption providers it is also the
// prefix written into stored values. The default-configuration names must therefore stay byte for
// byte what they have always been; the configured-value names exist so a provider stops reporting
// settings it is not using.
public class ProviderNamingTests
{
    [Fact]
    public void DefaultNames_AreUnchanged()
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
    [InlineData("SHA384", "ECDSA-P256-SHA384")]
    [InlineData("SHA512", "ECDSA-P256-SHA512")]
    public void Ecdsa_NameReflectsTheConfiguredHash(string hash, string expected)
    {
        Assert.Equal(expected, new ECDsaSignatureProvider(new HashAlgorithmName(hash)).ProviderName);
    }

    [Theory]
    [InlineData("SHA384", "RSA-2048-PKCS1-SHA384")]
    [InlineData("SHA512", "RSA-2048-PKCS1-SHA512")]
    public void RsaSignature_NameReflectsTheConfiguredHash(string hash, string expected)
    {
        Assert.Equal(expected, new RsaSignatureProvider(new HashAlgorithmName(hash)).ProviderName);
    }

    [Fact]
    public void RsaEncryption_NameReflectsTheConfiguredPadding()
    {
        Assert.Equal(
            "RSA-2048-PKCS1",
            new RsaEncryptionProvider(RSAEncryptionPadding.Pkcs1).ProviderName
        );
        Assert.Equal(
            "RSA-2048-OAEP-SHA512",
            new RsaEncryptionProvider(RSAEncryptionPadding.OaepSHA512).ProviderName
        );
    }
}
