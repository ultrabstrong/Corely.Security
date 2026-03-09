namespace Corely.Security.Hashing.Providers;

public interface IHashProvider
{
    string ProviderName { get; }
    string ProviderDescription { get; }
    string Hash(string value);
    bool Verify(string value, string hash);
}
