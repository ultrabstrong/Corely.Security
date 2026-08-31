using AutoFixture;
using Corely.Security.Keys;
using Corely.Security.Signature;
using Corely.Security.Signature.Providers;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.UnitTests.Signature.Providers;

public class SymmetricSignatureProviderBaseTests : SymmetricSignatureProviderGenericTests
{
    private class MockSymmetricKeyProvider : ISymmetricKeyProvider
    {
        private readonly Fixture _fixture = new();

        public byte[] CreateKey()
        {
            return _fixture.Create<byte[]>();
        }

        public bool IsKeyValid(ReadOnlySpan<byte> key) => true;
    }

    private class MockSignatureProvider : SymmetricSignatureProviderBase
    {
        public MockSignatureProvider()
            : base(TEST_PROVIDER_NAME) { }

        private readonly MockSymmetricKeyProvider _mockKeyProvider = new();

        private string lastValue = string.Empty;
        private string lastSignature = string.Empty;

        public override ISymmetricKeyProvider GetSymmetricKeyProvider() => _mockKeyProvider;
        public override SigningCredentials GetSigningCredentials(ReadOnlySpan<byte> key) => null!;

        protected override string SignInternal(string value, ReadOnlySpan<byte> key)
        {
            lastValue = value;
            lastSignature = $"{value}{Convert.ToBase64String(key)}";
            return lastSignature;
        }

        protected override bool VerifyInternal(string value, string signature, ReadOnlySpan<byte> key) =>
            lastValue == value
            && lastSignature == signature
            && lastSignature.EndsWith(Convert.ToBase64String(key));
    }

    private abstract class MockSymmetricSignatureProviderBase : SymmetricSignatureProviderBase
    {
        protected MockSymmetricSignatureProviderBase(string providerName)
            : base(providerName) { }

        public override ISymmetricKeyProvider GetSymmetricKeyProvider() => null!;
        public override SigningCredentials GetSigningCredentials(ReadOnlySpan<byte> key) => null!;
        protected override string SignInternal(string value, ReadOnlySpan<byte> key) => value;
        protected override bool VerifyInternal(string value, string signature, ReadOnlySpan<byte> key) => false;
    }

    private class NullMockSignatureProvider : MockSymmetricSignatureProviderBase
    {
        public NullMockSignatureProvider()
            : base(null!) { }

    }

    private class EmptyMockSignatureProvider : MockSymmetricSignatureProviderBase
    {
        public EmptyMockSignatureProvider()
            : base(string.Empty) { }

    }

    private class WhitespaceMockSignatureProvider : MockSymmetricSignatureProviderBase
    {
        public WhitespaceMockSignatureProvider()
            : base(" ") { }

    }

    private class ColonMockSignatureProvider : MockSymmetricSignatureProviderBase
    {
        public ColonMockSignatureProvider()
            : base("as:df") { }

    }

    private const string TEST_PROVIDER_NAME = "00";

    private readonly MockSignatureProvider _mockSignatureProvider = new();

    [Fact]
    public void NullProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new NullMockSignatureProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentNullException>(ex);
    }

    [Fact]
    public void EmptyProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new EmptyMockSignatureProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex);
    }

    [Fact]
    public void WhitespaceProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new WhitespaceMockSignatureProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex);
    }

    [Fact]
    public void ColonProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new ColonMockSignatureProvider());
        Assert.NotNull(ex);
        Assert.IsType<SignatureException>(ex);
    }

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(TEST_PROVIDER_NAME, _mockSignatureProvider.ProviderName);
    }

    [Fact]
    public override void GetSymmetricKeyProvider_ReturnsCorrectKeyProvider_ForImplementation()
    {
        var keyProvider = _mockSignatureProvider.GetSymmetricKeyProvider();

        Assert.NotNull(keyProvider);
        Assert.IsType<MockSymmetricKeyProvider>(keyProvider);
    }

    public override ISymmetricSignatureProvider GetSignatureProvider()
    {
        return new MockSignatureProvider();
    }
}
