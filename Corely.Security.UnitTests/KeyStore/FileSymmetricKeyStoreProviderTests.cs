using System.Security.Cryptography;
using System.Text;
using AutoFixture;
using Corely.Security.KeyStore;
using Moq.Protected;

namespace Corely.Security.UnitTests.KeyStore;

public class FileSymmetricKeyStoreProviderTests
{
    private readonly Fixture _fixture = new();
    private readonly FileSymmetricKeyStoreProvider _fileKeyStoreProvider;
    private readonly byte[] _fileKey = RandomNumberGenerator.GetBytes(32);

    public FileSymmetricKeyStoreProviderTests()
    {
        _fileKeyStoreProvider = MockReading(Convert.ToBase64String(_fileKey));
    }

    private FileSymmetricKeyStoreProvider MockReading(string fileContents)
    {
        var mock = new Mock<FileSymmetricKeyStoreProvider>(_fixture.Create<string>());
        mock.Protected()
            .Setup<byte[]>("GetFileBytes")
            .Returns(() => Encoding.UTF8.GetBytes(fileContents));
        return mock.Object;
    }

    [Fact]
    public void GetCurrentKey_ReturnsDecodedKey()
    {
        Assert.Equal(_fileKey, _fileKeyStoreProvider.GetCurrentKey());
    }

    // Key files are written by hand and by editors that append a newline.
    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("  ")]
    public void GetCurrentKey_IgnoresSurroundingWhitespace(string suffix)
    {
        var provider = MockReading(Convert.ToBase64String(_fileKey) + suffix);

        Assert.Equal(_fileKey, provider.GetCurrentKey());
    }

    [Fact]
    public void GetCurrentKey_Throws_WhenFileIsNotBase64()
    {
        var provider = MockReading("not base64 !!!");

        var ex = Record.Exception(provider.GetCurrentKey);

        Assert.NotNull(ex);
        Assert.IsType<KeyStoreException>(ex);
    }

    [Fact]
    public void GetCurrentVersion_ReturnsVersion1()
    {
        Assert.Equal(1, _fileKeyStoreProvider.GetCurrentVersion());
    }

    [Fact]
    public void Get_ReturnsTheKey_ForTheOnlyVersion()
    {
        Assert.Equal(_fileKey, _fileKeyStoreProvider.Get(1));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(99)]
    public void Get_Throws_ForAnyOtherVersion(int version)
    {
        var ex = Record.Exception(() => _fileKeyStoreProvider.Get(version));

        Assert.NotNull(ex);
        Assert.IsType<KeyStoreException>(ex);
        Assert.Equal(KeyStoreException.ErrorReason.InvalidVersion, ((KeyStoreException)ex).Reason);
    }
}
