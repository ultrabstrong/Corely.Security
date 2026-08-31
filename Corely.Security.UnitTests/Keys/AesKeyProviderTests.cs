using System.Security.Cryptography;
using Corely.Security.Keys;

namespace Corely.Security.UnitTests.Keys;

public class AesKeyProviderTests
{
    private readonly AesKeyProvider _aesKeyProvider = new();

    [Fact]
    public void CreateKey_ReturnsAKeyAesAccepts()
    {
        var key = _aesKeyProvider.CreateKey();

        using var aes = Aes.Create();
        var ex = Record.Exception(() => aes.Key = key);

        Assert.Null(ex);
    }

    [Fact]
    public void CreateKey_Returns256Bits()
    {
        Assert.Equal(32, _aesKeyProvider.CreateKey().Length);
    }

    [Fact]
    public void IsKeyValid_ReturnsTrue_WithKeyFromCreateKey()
    {
        Assert.True(_aesKeyProvider.IsKeyValid(_aesKeyProvider.CreateKey()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void IsKeyValid_ReturnsFalse_ForLengthsAesRejects(int length)
    {
        Assert.False(_aesKeyProvider.IsKeyValid(new byte[length]));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void IsKeyValid_ReturnsTrue_ForLengthsAesAccepts(int length)
    {
        Assert.True(_aesKeyProvider.IsKeyValid(new byte[length]));
    }
}
