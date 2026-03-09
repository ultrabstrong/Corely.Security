using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption.Providers;

public interface IAsymmetricEncryptionProvider
{
    string ProviderName { get; }
    string ProviderDescription { get; }
    IAsymmetricKeyProvider GetAsymmetricKeyProvider();
    string Encrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider);
    string Decrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider);
    string ReEncrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider);
    string? RemoveEncodedEncryptionData(string value);
}
