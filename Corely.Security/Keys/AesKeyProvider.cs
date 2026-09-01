using System.Security.Cryptography;

namespace Corely.Security.Keys;

internal sealed class AesKeyProvider : ISymmetricKeyProvider
{
    private const int AES_256_KEY_SIZE = 32;

    public byte[] CreateKey() => RandomNumberGenerator.GetBytes(AES_256_KEY_SIZE);

    public bool IsKeyValid(ReadOnlySpan<byte> key) => key.Length is 16 or 24 or 32;
}
