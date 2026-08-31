namespace Corely.Security.KeyStore;

public interface IAsymmetricKeyStoreProvider
{
    int GetCurrentVersion();

    /// <summary>
    /// Returns the key pair for <paramref name="version"/>. The caller owns the returned arrays
    /// and is responsible for zeroing the private key; the provider base classes do this
    /// automatically.
    /// </summary>
    (byte[] PublicKey, byte[] PrivateKey) Get(int version);

    /// <inheritdoc cref="Get(int)"/>
    (byte[] PublicKey, byte[] PrivateKey) GetCurrentKeys();
}
