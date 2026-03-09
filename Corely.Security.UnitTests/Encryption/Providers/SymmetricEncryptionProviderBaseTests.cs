using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;

namespace Corely.Security.UnitTests.Encryption.Providers;

public sealed class SymmetricEncryptionProviderBaseTests : SymmetricEncryptionProviderGenericTests
{
    private class MockSymmetricKeyProvider : ISymmetricKeyProvider
    {
        public string CreateKey() => string.Empty;
        public bool IsKeyValid(string key) => true;
    }

    private class MockEncryptionProvider : SymmetricEncryptionProviderBase
    {
        public override string ProviderName => TEST_PROVIDER_NAME;
        private readonly MockSymmetricKeyProvider _mockKeyProvider = new();
        public override ISymmetricKeyProvider GetSymmetricKeyProvider() => _mockKeyProvider;
        protected override string EncryptInternal(string value, string key) => $"{Guid.NewGuid()}{value}";
        protected override string DecryptInternal(string value, string key) => value[36..];
    }

    private abstract class MockSymmetricEncryptionProviderBase : SymmetricEncryptionProviderBase
    {
        public override ISymmetricKeyProvider GetSymmetricKeyProvider() => null!;
        protected override string EncryptInternal(string value, string key) => value;
        protected override string DecryptInternal(string value, string key) => value;
    }

    private class NullMockEncryptionProvider : MockSymmetricEncryptionProviderBase
    {
        public override string ProviderName => null!;
    }

    private class EmptyMockEncryptionProvider : MockSymmetricEncryptionProviderBase
    {
        public override string ProviderName => string.Empty;
    }

    private class WhitespaceMockEncryptionProvider : MockSymmetricEncryptionProviderBase
    {
        public override string ProviderName => " ";
    }

    private class ColonMockEncryptionProvider : MockSymmetricEncryptionProviderBase
    {
        public override string ProviderName => "as:df";
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
    public override void GetSymmetricKeyProvider_ReturnsCorrectKeyProvider_ForImplementation()
    {
        var keyProvider = _mockEncryptionProvider.GetSymmetricKeyProvider();

        Assert.NotNull(keyProvider);
        Assert.IsType<MockSymmetricKeyProvider>(keyProvider);
    }

    public override ISymmetricEncryptionProvider GetEncryptionProvider()
    {
        return new MockEncryptionProvider();
    }
}
