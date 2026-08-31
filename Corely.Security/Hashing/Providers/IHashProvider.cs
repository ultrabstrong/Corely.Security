namespace Corely.Security.Hashing.Providers;

public interface IHashProvider
{
    /// <summary>
    /// Stable identifier for this provider. It is the factory lookup key and the prefix written into every hash this provider produces, so changing it strands
    /// stored hashes unless the old name stays registered as a read alias.
    /// </summary>
    /// <remarks>
    /// Treat this as opaque. It resembles an algorithm description for readability, but it is an
    /// identity, and the two pull apart: it must encode what the provider is <em>configured</em>
    /// with, never what the key it is handed happens to be. Key size in particular comes from the
    /// key store at call time and cannot be reflected here accurately.
    /// Use <see cref="ProviderDescription"/> for anything shown to a human.
    /// </remarks>
    string ProviderName { get; }
    string ProviderDescription { get; }
    string Hash(string value);
    bool Verify(string value, string hash);
    bool NeedsRehash(string hash) => false;
}
