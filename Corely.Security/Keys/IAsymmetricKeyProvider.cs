namespace Corely.Security.Keys;

public interface IAsymmetricKeyProvider
{
    /// <summary>
    /// Creates a new key pair. The caller owns both arrays and should zero the private key with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/> once it has
    /// been persisted.
    /// </summary>
    (byte[] PublicKey, byte[] PrivateKey) CreateKeys();

    bool IsKeyValid(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey);
}
