using Corely.Security.Hashing;
using Corely.Security.Hashing.Providers;

namespace Corely.Security.UnitTests.Hashing.Providers;

public class Sha256SaltedHashProviderTests : SaltedHashProviderGenericTests
{
    private readonly Sha256SaltedHashProvider _sha256SaltedHashProvider = new();

    protected override IHashProvider HashProvider => _sha256SaltedHashProvider;

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(HashConstants.SALTED_SHA256_CODE, _sha256SaltedHashProvider.ProviderName);
    }

    [Fact]
    public void ProviderDescription_ReturnsNonDefaultValue()
    {
        var description = _sha256SaltedHashProvider.ProviderDescription;

        Assert.False(string.IsNullOrWhiteSpace(description));
        Assert.NotEqual(_sha256SaltedHashProvider.GetType().Name, description);
    }
}
