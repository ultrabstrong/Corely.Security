using System.Security.Cryptography;
using Corely.Security.Encryption.Providers;

namespace Corely.Security.UnitTests.Encryption.Providers;

public class RSAEncryptionPaddingExtensionsTests
{
    [Fact]
    public void ShortName_NamesOaepWithItsHash()
    {
        Assert.Equal("OAEP-SHA256", RSAEncryptionPadding.OaepSHA256.ShortName());
    }

    [Fact]
    public void ShortName_NamesPkcs1()
    {
        Assert.Equal("PKCS1", RSAEncryptionPadding.Pkcs1.ShortName());
    }
}
