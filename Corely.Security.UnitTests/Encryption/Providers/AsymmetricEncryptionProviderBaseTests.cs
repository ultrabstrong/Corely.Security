using AutoFixture;
using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;

namespace Corely.Security.UnitTests.Encryption.Providers;

public sealed class AsymmetricEncryptionProviderBaseTests : AsymmetricEncryptionProviderGenericTests
{
    private class MockAsymmetricKeyProvider : IAsymmetricKeyProvider
    {
        private readonly Fixture _fixture = new();

        public (string PublicKey, string PrivateKey) CreateKeys() => _fixture.Create<(string, string)>();

        public bool IsKeyValid(string publicKey, string privateKey) => true;
    }

    private class MockEncryptionProvider : AsymmetricEncryptionProviderBase
    {
        public MockEncryptionProvider()
            : base(TEST_PROVIDER_NAME) { }

        private readonly MockAsymmetricKeyProvider _mockKeyProvider = new();
        public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => _mockKeyProvider;
        protected override string EncryptInternal(string value, string key) => $"{Guid.NewGuid()}{value}";
        protected override string DecryptInternal(string value, string key) => value[36..];
    }

    private abstract class MockAsymmetricEncryptionProviderBase : AsymmetricEncryptionProviderBase
    {
        protected MockAsymmetricEncryptionProviderBase(string providerName)
            : base(providerName) { }

        public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => null!;
        protected override string EncryptInternal(string value, string key) => value;
        protected override string DecryptInternal(string value, string key) => value;
    }

    private class NullMockEncryptionProvider : MockAsymmetricEncryptionProviderBase
    {
        public NullMockEncryptionProvider()
            : base(null!) { }

    }

    private class EmptyMockEncryptionProvider : MockAsymmetricEncryptionProviderBase
    {
        public EmptyMockEncryptionProvider()
            : base(string.Empty) { }

    }

    private class WhitespaceMockEncryptionProvider : MockAsymmetricEncryptionProviderBase
    {
        public WhitespaceMockEncryptionProvider()
            : base(" ") { }

    }

    private class ColonMockEncryptionProvider : MockAsymmetricEncryptionProviderBase
    {
        public ColonMockEncryptionProvider()
            : base("as:df") { }

    }

    private const string TEST_PROVIDER_NAME = "00";

    private readonly MockEncryptionProvider _mockEncryptionProvider = new();

    [Fact]
    public void NullProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new NullMockEncryptionProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentNullException>(ex);
    }

    [Fact]
    public void EmptyProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new EmptyMockEncryptionProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex);
    }

    [Fact]
    public void WhitespaceProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new WhitespaceMockEncryptionProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex);
    }

    [Fact]
    public void ColonProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new ColonMockEncryptionProvider());
        Assert.NotNull(ex);
        Assert.IsType<EncryptionException>(ex);
    }

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(TEST_PROVIDER_NAME, _mockEncryptionProvider.ProviderName);
    }

    [Fact]
    public override void GetAsymmetricKeyProvider_ReturnsCorrectKeyProvider_ForImplementation()
    {
        var keyProvider = _mockEncryptionProvider.GetAsymmetricKeyProvider();

        Assert.NotNull(keyProvider);
        Assert.IsType<MockAsymmetricKeyProvider>(keyProvider);
    }

    public override IAsymmetricEncryptionProvider GetEncryptionProvider()
    {
        return new MockEncryptionProvider();
    }
}
