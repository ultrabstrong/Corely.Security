using Corely.Security.Secrets;
using Corely.Security.UnitTests.ClassData;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.UnitTests.Secrets;

public class RandomSecretProviderTests
{
    private readonly RandomSecretProvider _secretProvider = new();

    [Fact]
    public void Constructor_UsesDefaultSecretSize()
    {
        var provider = new RandomSecretProvider();
        var secretBytes = Base64UrlEncoder.DecodeBytes(provider.CreateSecret());

        Assert.Equal(RandomSecretProvider.DEFAULT_SECRET_SIZE, secretBytes.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_Throws_WithInvalidSecretSize(int secretSize)
    {
        var ex = Record.Exception(() => new RandomSecretProvider(secretSize));

        Assert.NotNull(ex);
        Assert.IsType<ArgumentOutOfRangeException>(ex);
    }

    [Fact]
    public void CreateSecret_ReturnsValidUrlSafeSecret()
    {
        var secret = _secretProvider.CreateSecret();

        Assert.DoesNotContain("+", secret);
        Assert.DoesNotContain("/", secret);
        Assert.DoesNotContain("=", secret);
        Assert.Equal(
            RandomSecretProvider.DEFAULT_SECRET_SIZE,
            Base64UrlEncoder.DecodeBytes(secret).Length
        );
    }

    [Fact]
    public void CreateSecret_UsesSecretSize_FromConstructor()
    {
        var secretSize = 64;
        var provider = new RandomSecretProvider(secretSize);
        var secret = provider.CreateSecret();

        Assert.Equal(secretSize, Base64UrlEncoder.DecodeBytes(secret).Length);
    }

    [Fact]
    public void IsSecretValid_ReturnsTrue_WithSecretFromCreateSecret()
    {
        var secret = _secretProvider.CreateSecret();

        Assert.True(_secretProvider.IsSecretValid(secret));
    }

    [Theory, ClassData(typeof(NullEmptyAndWhitespace))]
    public void IsSecretValid_ReturnsFalse_WithNullEmptyOrWhitespaceSecret(string secret)
    {
        Assert.False(_secretProvider.IsSecretValid(secret));
    }

    [Fact]
    public void IsSecretValid_ReturnsFalse_ForInvalidSecret()
    {
        Assert.False(_secretProvider.IsSecretValid("not-a-valid-secret"));
    }
}
