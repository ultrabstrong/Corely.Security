using Corely.Security.Hashing;
using Corely.Security.Hashing.Providers;

namespace Corely.Security.UnitTests.Hashing.Providers;

public class Sha512SaltedHashProviderTests : SaltedHashProviderGenericTests
{
    private readonly Sha512SaltedHashProvider _sha512SaltedHashProvider = new();

    protected override IHashProvider HashProvider => _sha512SaltedHashProvider;

    [Fact]
    public override void ProviderName_ReturnsCorrectValue_ForImplementation()
    {
        Assert.Equal(HashConstants.SALTED_SHA512_CODE, _sha512SaltedHashProvider.ProviderName);
    }

    [Fact]
    public void ProviderDescription_ReturnsNonDefaultValue()
    {
        var description = _sha512SaltedHashProvider.ProviderDescription;

        Assert.False(string.IsNullOrWhiteSpace(description));
        Assert.NotEqual(_sha512SaltedHashProvider.GetType().Name, description);
    }
}
