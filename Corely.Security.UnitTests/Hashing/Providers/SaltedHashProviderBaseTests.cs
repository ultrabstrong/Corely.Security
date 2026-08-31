using AutoFixture;
using Corely.Security.Hashing;
using Corely.Security.Hashing.Providers;

namespace Corely.Security.UnitTests.Hashing.Providers;

public class SaltedHashProviderBaseTests : SaltedHashProviderGenericTests
{
    private class MockHashProvider : SaltedHashProviderBase
    {
        public MockHashProvider()
            : base(TEST_PROVIDER_NAME) { }

        protected override byte[] HashInternal(byte[] value) => value;
    }

    private class NullMockHashProvider : SaltedHashProviderBase
    {
        public NullMockHashProvider()
            : base(null!) { }

        protected override byte[] HashInternal(byte[] value) => value;
    }

    private class EmptyMockHashProvider : SaltedHashProviderBase
    {
        public EmptyMockHashProvider()
            : base(string.Empty) { }

        protected override byte[] HashInternal(byte[] value) => value;
    }

    private class WhitespaceMockHashProvider : SaltedHashProviderBase
    {
        public WhitespaceMockHashProvider()
            : base(" ") { }

        protected override byte[] HashInternal(byte[] value) => value;
    }

    private class ColonMockHashProvider : SaltedHashProviderBase
    {
        public ColonMockHashProvider()
            : base("as:df") { }

        protected override byte[] HashInternal(byte[] value) => value;
    }

    protected override IHashProvider HashProvider => _mockHashProvider;

    private const string TEST_PROVIDER_NAME = "00";

    private readonly MockHashProvider _mockHashProvider = new();

    [Fact]
    public void NullProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new NullMockHashProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentNullException>(ex);
    }

    [Fact]
    public void EmptyProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new EmptyMockHashProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex);
    }

    [Fact]
    public void WhitespaceProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new WhitespaceMockHashProvider());
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex);
    }

    [Fact]
    public void ColonProviderName_Throws_OnBuild()
    {
        var ex = Record.Exception(() => new ColonMockHashProvider());
        Assert.NotNull(ex);
        Assert.IsType<HashException>(ex);
    }

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(TEST_PROVIDER_NAME, _mockHashProvider.ProviderName);
    }

    [Theory]
    [InlineData("asdf")]
    [InlineData(TEST_PROVIDER_NAME)]
    [InlineData($"{TEST_PROVIDER_NAME}:asdf")]
    public void Verify_ReturnsFalse_WithInvalidHash(string hash)
    {
        var fixture = new Fixture();
        Assert.False(_mockHashProvider.Verify(fixture.Create<string>(), hash));
    }
}
