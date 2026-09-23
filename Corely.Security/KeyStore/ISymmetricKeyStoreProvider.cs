namespace Corely.Security.KeyStore;

public interface ISymmetricKeyStoreProvider
{
    int GetCurrentVersion();

    byte[] Get(int version);

    byte[] GetCurrentKey();
}
