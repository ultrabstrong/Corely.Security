namespace Corely.Security.Hashing.Providers;

public interface IHashProvider
{
    string ProviderName { get; }
    string ProviderDescription { get; }
    string Hash(string value);
    bool Verify(string value, string hash);

    /// <summary>
    /// Whether an existing hash was produced with weaker parameters than this provider currently
    /// uses, and should be recomputed. Lets a caller raise the work factor over time and upgrade
    /// stored hashes on next successful verification, rather than forcing a password reset.
    ///
    /// Providers with no tunable work factor return false.
    /// </summary>
    bool NeedsRehash(string hash) => false;
}
