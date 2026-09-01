using Corely.Security.Keys;

namespace Corely.Security.UnitTests.Keys;

public class RandomKeyProviderTests
{
    private readonly RandomKeyProvider _randomKeyProvider = new();

    [Fact]
    public void Constructor_UsesDefaultKeySize()
    {
        Assert.Equal(
            RandomKeyProvider.DEFAULT_KEY_SIZE,
            new RandomKeyProvider().CreateKey().Length
        );
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_Throws_WithInvalidKeySize(int keySize)
    {
        var ex = Record.Exception(() => new RandomKeyProvider(keySize));
        Assert.NotNull(ex);
        Assert.IsType<ArgumentOutOfRangeException>(ex);
    }

    [Fact]
    public void CreateKey_UsesKeyLength_FromConstructor()
    {
        Assert.Equal(64, new RandomKeyProvider(64).CreateKey().Length);
    }

    [Fact]
    public void CreateKey_ReturnsADistinctKeyEachTime()
    {
        Assert.NotEqual(_randomKeyProvider.CreateKey(), _randomKeyProvider.CreateKey());
    }

    [Fact]
    public void IsKeyValid_ReturnsTrue_WithKeyFromCreateKey()
    {
        Assert.True(_randomKeyProvider.IsKeyValid(_randomKeyProvider.CreateKey()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void IsKeyValid_ReturnsFalse_ForTheWrongLength(int length)
    {
        Assert.False(_randomKeyProvider.IsKeyValid(new byte[length]));
    }
}
