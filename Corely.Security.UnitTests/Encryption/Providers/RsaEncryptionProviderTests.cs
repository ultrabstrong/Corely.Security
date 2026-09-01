using System.Security.Cryptography;
using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;

namespace Corely.Security.UnitTests.Encryption.Providers;

public class RsaEncryptionProviderTests : AsymmetricEncryptionProviderGenericTests
{
    private readonly RsaEncryptionProvider _rsaEncryptionProvider = new(
        RSAEncryptionPadding.OaepSHA256
    );

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(AsymmetricEncryptionConstants.RSA_CODE, _rsaEncryptionProvider.ProviderName);
    }

    [Fact]
    public void ProviderDescription_ReturnsNonDefaultValue()
    {
        var description = _rsaEncryptionProvider.ProviderDescription;

        Assert.False(string.IsNullOrWhiteSpace(description));
        Assert.NotEqual(_rsaEncryptionProvider.GetType().Name, description);
    }

    [Fact]
    public override void GetAsymmetricKeyProvider_ReturnsCorrectKeyProvider_ForImplementation()
    {
        var keyProvider = _rsaEncryptionProvider.GetAsymmetricKeyProvider();

        Assert.NotNull(keyProvider);
        Assert.IsType<RsaKeyProvider>(keyProvider);
    }

    public override IAsymmetricEncryptionProvider GetEncryptionProvider()
    {
        return new RsaEncryptionProvider(RSAEncryptionPadding.OaepSHA256);
    }
}
