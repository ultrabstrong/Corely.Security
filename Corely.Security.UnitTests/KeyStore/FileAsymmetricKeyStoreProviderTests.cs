using System.Text;
using AutoFixture;
using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Moq.Protected;

namespace Corely.Security.UnitTests.KeyStore;

public class FileAsymmetricKeyStoreProviderTests
{
    private readonly Fixture _fixture = new();
    private readonly FileAsymmetricKeyStoreProvider _fileKeyStoreProvider;
    private readonly byte[] _filePublicKey;
    private readonly byte[] _filePrivateKey;

    public FileAsymmetricKeyStoreProviderTests()
    {
        (_filePublicKey, _filePrivateKey) = new EcdsaKeyProvider().CreateKeys();
        _fileKeyStoreProvider = MockReading(
            Convert.ToBase64String(_filePublicKey)
                + Environment.NewLine
                + Convert.ToBase64String(_filePrivateKey)
        );
    }

    private FileAsymmetricKeyStoreProvider MockReading(string fileContents)
    {
        var mock = new Mock<FileAsymmetricKeyStoreProvider>(_fixture.Create<string>());
        mock.Protected()
            .Setup<byte[]>("GetFileBytes")
            .Returns(() => Encoding.UTF8.GetBytes(fileContents));
        return mock.Object;
    }

    [Fact]
    public void GetCurrentKeys_ReturnsDecodedKeys()
    {
        var (publicKey, privateKey) = _fileKeyStoreProvider.GetCurrentKeys();

        Assert.Equal(_filePublicKey, publicKey);
        Assert.Equal(_filePrivateKey, privateKey);
    }

    [Fact]
    public void GetCurrentKeys_ReadsBothLineEndings()
    {
        var provider = MockReading(
            Convert.ToBase64String(_filePublicKey)
                + "\n"
                + Convert.ToBase64String(_filePrivateKey)
                + "\n"
        );

        var (publicKey, privateKey) = provider.GetCurrentKeys();

        Assert.Equal(_filePublicKey, publicKey);
        Assert.Equal(_filePrivateKey, privateKey);
    }

    [Fact]
    public void GetCurrentKeys_Throws_WithOnlyOneLine()
    {
        var provider = MockReading(Convert.ToBase64String(_filePublicKey));

        var ex = Record.Exception(() => provider.GetCurrentKeys());

        Assert.NotNull(ex);
        Assert.IsType<KeyStoreException>(ex);
        Assert.Equal(
            KeyStoreException.ErrorReason.CurrentKeyNotFound,
            ((KeyStoreException)ex).Reason
        );
    }

    [Fact]
    public void GetCurrentVersion_ReturnsVersion1()
    {
        Assert.Equal(1, _fileKeyStoreProvider.GetCurrentVersion());
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
