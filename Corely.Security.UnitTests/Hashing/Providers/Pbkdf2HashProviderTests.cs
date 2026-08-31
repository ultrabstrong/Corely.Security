using Corely.Security.Hashing;
using Corely.Security.Hashing.Providers;

namespace Corely.Security.UnitTests.Hashing.Providers;

public class Pbkdf2HashProviderTests : SaltedHashProviderGenericTests
{
    private const int TEST_ITERATIONS = 1_000;

    private readonly Pbkdf2HashProvider _provider = new(TEST_ITERATIONS);

    protected override IHashProvider HashProvider => _provider;

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(HashConstants.PBKDF2_SHA256_CODE, _provider.ProviderName);
    }

    [Fact]
    public void DefaultIterations_MeetsOwaspFloor()
    {
        Assert.True(Pbkdf2HashProvider.DEFAULT_ITERATIONS >= 600_000);
        Assert.Equal(Pbkdf2HashProvider.DEFAULT_ITERATIONS, new Pbkdf2HashProvider().Iterations());
    }

    [Fact]
    public void Hash_EmbedsIterationCount()
    {
        var hash = _provider.Hash("password");

        var parts = hash.Split(':');
        Assert.Equal(4, parts.Length);
        Assert.Equal(HashConstants.PBKDF2_SHA256_CODE, parts[0]);
        Assert.Equal(TEST_ITERATIONS.ToString(), parts[1]);
    }

    [Fact]
    public void Hash_UsesADistinctSaltEachTime()
    {
        var first = _provider.Hash("password").Split(':')[2];
        var second = _provider.Hash("password").Split(':')[2];

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Constructor_Throws_WithNonPositiveIterations()
    {
        Assert.Throws<HashException>(() => new Pbkdf2HashProvider(0));
        Assert.Throws<HashException>(() => new Pbkdf2HashProvider(-1));
    }

    [Fact]
    public void NeedsRehash_IsFalse_ForAHashAtTheCurrentWorkFactor()
    {
        var hash = _provider.Hash("password");

        Assert.False(_provider.NeedsRehash(hash));
    }

    [Fact]
    public void NeedsRehash_IsTrue_ForAHashBelowTheCurrentWorkFactor()
    {
        var weak = new Pbkdf2HashProvider(TEST_ITERATIONS / 2).Hash("password");

        Assert.True(_provider.NeedsRehash(weak));
    }

    [Fact]
    public void NeedsRehash_IsFalse_ForAHashAboveTheCurrentWorkFactor()
    {
        var strong = new Pbkdf2HashProvider(TEST_ITERATIONS * 2).Hash("password");

        Assert.False(_provider.NeedsRehash(strong));
    }

    [Fact]
    public void NeedsRehash_IsTrue_ForAMalformedHash()
    {
        Assert.True(_provider.NeedsRehash("garbage"));
    }

    [Fact]
    public void AHashFromAnEarlierWorkFactor_StillVerifies()
    {
        var weak = new Pbkdf2HashProvider(TEST_ITERATIONS / 2).Hash("password");

        Assert.True(_provider.Verify("password", weak));
    }

    [Fact]
    public void SaltedShaHashes_AreNotVerifiedByThisProvider()
    {
        var shaHash = new Sha256SaltedHashProvider().Hash("password");

        Assert.False(_provider.Verify("password", shaHash));
    }

    [Theory]
    [InlineData("PBKDF2-SHA256:notanumber:AAAA:AAAA")]
    [InlineData("PBKDF2-SHA256:0:AAAA:AAAA")]
    [InlineData("PBKDF2-SHA256:-5:AAAA:AAAA")]
    [InlineData("PBKDF2-SHA256:1000:!!!:AAAA")]
    [InlineData("PBKDF2-SHA256:1000:AAAA:!!!")]
    [InlineData("PBKDF2-SHA256:1000:AAAA")]
    [InlineData("PBKDF2-SHA256:1000:AAAA:AAAA:extra")]
    public void Verify_ReturnsFalse_WithMalformedPbkdf2Hash(string hash)
    {
        Assert.False(_provider.Verify("password", hash));
    }
}

file static class Pbkdf2HashProviderExtensions
{
    public static int Iterations(this Pbkdf2HashProvider provider) =>
        int.Parse(provider.Hash("probe").Split(':')[1]);
}
