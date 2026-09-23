namespace Corely.Security.KeyStore;

public interface IAsymmetricKeyStoreProvider
{
    int GetCurrentVersion();

    (byte[] PublicKey, byte[] PrivateKey) Get(int version);

    (byte[] PublicKey, byte[] PrivateKey) GetCurrentKeys();
}
