using AutoFixture;
using Corely.Security.Keys;
using Corely.Security.Signature;
using Corely.Security.Signature.Providers;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.UnitTests.Signature.Providers;

public sealed class AsymmetricSignatureProviderBaseTests : AsymmetricSignatureProviderGenericTests
{
    private class MockAsymmetricKeyProvider : IAsymmetricKeyProvider
    {
        private readonly Fixture _fixture = new();

        public (byte[] PublicKey, byte[] PrivateKey) CreateKeys()
        {
            var key = _fixture.Create<byte[]>();
            return (key, key); // This allows mocking signature verification success / failure
        }

        public bool IsKeyValid(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey) => true;
    }

    private class MockSignatureProvider : AsymmetricSignatureProviderBase
    {
        public MockSignatureProvider()
            : base(TEST_PROVIDER_NAME) { }

        private readonly MockAsymmetricKeyProvider _mockKeyProvider = new();

        private string lastValue = string.Empty;
        private string lastSignature = string.Empty;

        public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => _mockKeyProvider;

        public override SigningCredentials GetSigningCredentials(
            ReadOnlySpan<byte> key,
            bool isKeyPrivate
        ) => null!;

        protected override string SignInternal(string value, ReadOnlySpan<byte> privateKey)
        {
            lastValue = value;
            lastSignature = $"{value}{Convert.ToBase64String(privateKey)}";
            return lastSignature;
        }

        protected override bool VerifyInternal(
            string value,
            string signature,
            ReadOnlySpan<byte> publicKey
        ) =>
            lastValue == value
            && lastSignature == signature
            && lastSignature.EndsWith(Convert.ToBase64String(publicKey));
    }

    private abstract class MockAsymmetricSignatureProviderBase : AsymmetricSignatureProviderBase
    {
        protected MockAsymmetricSignatureProviderBase(string providerName)
            : base(providerName) { }

        public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => null!;

        public override SigningCredentials GetSigningCredentials(
            ReadOnlySpan<byte> key,
            bool isKeyPrivate
        ) => null!;

        protected override string SignInternal(string value, ReadOnlySpan<byte> privateKey) =>
            value;

        protected override bool VerifyInternal(
            string value,
            string signature,
            ReadOnlySpan<byte> publicKey
        ) => false;
    }

    private class NullMockSignatureProvider : MockAsymmetricSignatureProviderBase
    {
        public NullMockSignatureProvider()
            : base(null!) { }
    }

    private class EmptyMockSignatureProvider : MockAsymmetricSignatureProviderBase
    {
        public EmptyMockSignatureProvider()
            : base(string.Empty) { }
    }

    private class WhitespaceMockSignatureProvider : MockAsymmetricSignatureProviderBase
    {
        public WhitespaceMockSignatureProvider()
            : base(" ") { }
    }

    private class ColonMockSignatureProvider : MockAsymmetricSignatureProviderBase
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
    public override void GetAsymmetricKeyProvider_ReturnsCorrectKeyProvider_ForImplementation()
    {
        var keyProvider = _mockSignatureProvider.GetAsymmetricKeyProvider();

        Assert.NotNull(keyProvider);
        Assert.IsType<MockAsymmetricKeyProvider>(keyProvider);
    }

    public override IAsymmetricSignatureProvider GetSignatureProvider()
    {
        return new MockSignatureProvider();
    }
}
