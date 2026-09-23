namespace Corely.Security.Hashing.Providers;

public interface IHashProvider
{
    // Written into every stored value: renaming strands data unless the old name stays a read alias.
    string ProviderName { get; }
    string ProviderDescription { get; }
    string Hash(string value);
    bool Verify(string value, string hash);
    bool NeedsRehash(string hash) => false;
}
