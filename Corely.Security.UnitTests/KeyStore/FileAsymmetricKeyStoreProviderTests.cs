using AutoFixture;
using Corely.Security.KeyStore;
using Moq.Protected;

namespace Corely.Security.UnitTests.KeyStore;

public class FileAsymmetricKeyStoreProviderTests
{
    private readonly Fixture _fixture = new();
    private readonly FileAsymmetricKeyStoreProvider _fileKeyStoreProvider;
    private readonly string _filePublicKey;
    private readonly string _filePrivateKey;

    public FileAsymmetricKeyStoreProviderTests()
    {
        _filePublicKey = _fixture.Create<string>();
        _filePrivateKey = _fixture.Create<string>();
        var fileKeyStoreProvider = new Mock<FileAsymmetricKeyStoreProvider>(_fixture.Create<string>());
        fileKeyStoreProvider.Protected()
            .Setup<string>("GetFileContents")
            .Returns(() => $"{_filePublicKey}{Environment.NewLine}{_filePrivateKey}");
        _fileKeyStoreProvider = fileKeyStoreProvider.Object;
    }

    [Fact]
    public void GetCurrentKey_ReturnsKey()
    {
        var (publicKey, privateKey) = _fileKeyStoreProvider.GetCurrentKeys();
        Assert.Equal(_filePublicKey, publicKey);
        Assert.Equal(_filePrivateKey, privateKey);
    }

    [Fact]
    public void GetCurrentVersion_ReturnsVersion1()
    {
        var version = _fileKeyStoreProvider.GetCurrentVersion();
        Assert.Equal(1, version);
    }

    [Fact]
    public void Get_ReturnsTheKeys_ForTheOnlyVersion()
    {
        var (publicKey, privateKey) = _fileKeyStoreProvider.Get(1);
        Assert.Equal(_filePublicKey, publicKey);
        Assert.Equal(_filePrivateKey, privateKey);
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
