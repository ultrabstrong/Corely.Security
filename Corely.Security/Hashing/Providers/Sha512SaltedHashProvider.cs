using System.Security.Cryptography;

namespace Corely.Security.Hashing.Providers;

internal sealed class Sha512SaltedHashProvider : SaltedHashProviderBase
{
    public Sha512SaltedHashProvider()
        : base(HashConstants.SALTED_SHA512_CODE) { }

    public override string ProviderDescription =>
        "SHA512 salted hash. A 16-byte random salt is generated per operation and prepended to the input before hashing. Output format: {ProviderName}:{Base64(salt + hash)}. Salt is embedded in the output for verification.";

    protected override byte[] HashInternal(byte[] value)
    {
        return SHA512.HashData(value);
    }
}
