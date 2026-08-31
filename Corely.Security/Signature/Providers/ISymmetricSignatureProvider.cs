using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.Signature.Providers;

public interface ISymmetricSignatureProvider
{
    /// <summary>
    /// Stable identifier for this provider. It is the factory lookup key. Signature output carries no prefix, so this name is not embedded in stored data.
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
    ISymmetricKeyProvider GetSymmetricKeyProvider();
    string Sign(string data, ISymmetricKeyStoreProvider keyStoreProvider);
    bool Verify(string data, string signature, ISymmetricKeyStoreProvider keyStoreProvider);
    SigningCredentials GetSigningCredentials(string key);
}
