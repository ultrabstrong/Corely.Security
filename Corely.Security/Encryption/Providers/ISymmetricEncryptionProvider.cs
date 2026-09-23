using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption.Providers;

public interface ISymmetricEncryptionProvider
{
    // Written into every stored value: renaming strands data unless the old name stays a read alias.
    string ProviderName { get; }
    string ProviderDescription { get; }
    ISymmetricKeyProvider GetSymmetricKeyProvider();
    string Encrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider);
    string Decrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider);
    string ReEncrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider);
    string? RemoveEncodedEncryptionData(string value);
}
