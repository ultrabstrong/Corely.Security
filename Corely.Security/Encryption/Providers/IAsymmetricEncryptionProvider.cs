using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption.Providers;

public interface IAsymmetricEncryptionProvider
{
    /// <summary>
    /// Stable identifier for this provider. It is the factory lookup key and the prefix written into every value this provider encrypts, so changing it strands
    /// stored data unless the old name stays registered as a read alias.
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
    IAsymmetricKeyProvider GetAsymmetricKeyProvider();
    string Encrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider);
    string Decrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider);
    string ReEncrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider);
    string? RemoveEncodedEncryptionData(string value);
}
