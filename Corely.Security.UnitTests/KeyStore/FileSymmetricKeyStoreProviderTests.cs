using AutoFixture;
using Corely.Security.KeyStore;
using Moq.Protected;

namespace Corely.Security.UnitTests.KeyStore;

public class FileSymmetricKeyStoreProviderTests
{
    private readonly Fixture _fixture = new();
    private readonly FileSymmetricKeyStoreProvider _fileKeyStoreProvider;
    private readonly string _fileKey;

    public FileSymmetricKeyStoreProviderTests()
    {
        _fileKey = _fixture.Create<string>();
        var fileKeyStoreProvider = new Mock<FileSymmetricKeyStoreProvider>(_fixture.Create<string>());
        fileKeyStoreProvider.Protected()
            .Setup<string>("GetFileContents")
            .Returns(() => _fileKey);
        _fileKeyStoreProvider = fileKeyStoreProvider.Object;
    }

    [Fact]
    public void GetCurrentKey_ReturnsKey()
    {
        var key = _fileKeyStoreProvider.GetCurrentKey();
        Assert.Equal(_fileKey, key);
    }

    [Fact]
    public void GetCurrentVersion_ReturnsVersion1()
    {
        var version = _fileKeyStoreProvider.GetCurrentVersion();
        Assert.Equal(1, version);
    }

    [Fact]
    public void Get_ReturnsTheKey_ForTheOnlyVersion()
    {
        var key = _fileKeyStoreProvider.Get(1);
        Assert.Equal(_fileKey, key);
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
