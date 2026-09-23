namespace Corely.Security.Keys;

public interface IAsymmetricKeyProvider
{
    (byte[] PublicKey, byte[] PrivateKey) CreateKeys();

    bool IsKeyValid(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey);
}
