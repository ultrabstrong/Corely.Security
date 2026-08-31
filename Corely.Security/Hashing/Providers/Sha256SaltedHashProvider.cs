using System.Security.Cryptography;

namespace Corely.Security.Hashing.Providers;

internal sealed class Sha256SaltedHashProvider : SaltedHashProviderBase
{
    public Sha256SaltedHashProvider()
        : base(HashConstants.SALTED_SHA256_CODE) { }

    public override string ProviderDescription =>
        "SHA256 salted hash. A 16-byte random salt is generated per operation and prepended to the input before hashing. Output format: {ProviderName}:{Base64(salt + hash)}. Salt is embedded in the output for verification.";

    protected override byte[] HashInternal(byte[] value)
    {
        return SHA256.HashData(value);
    }
}
