namespace Corely.Security.KeyStore;

public interface ISymmetricKeyStoreProvider
{
    int GetCurrentVersion();

    /// <summary>
    /// Returns the key for <paramref name="version"/>. The caller owns the returned array and is
    /// responsible for zeroing it; the provider base classes do this automatically.
    /// </summary>
    byte[] Get(int version);

    /// <inheritdoc cref="Get(int)"/>
    byte[] GetCurrentKey();
}
