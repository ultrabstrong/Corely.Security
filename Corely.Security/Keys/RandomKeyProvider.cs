using System.Security.Cryptography;

namespace Corely.Security.Keys;

internal sealed class RandomKeyProvider : ISymmetricKeyProvider
{
    public const int DEFAULT_KEY_SIZE = 32;

    private readonly int _keySize;

    public RandomKeyProvider(int keySize = DEFAULT_KEY_SIZE)
    {
        if (keySize < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(keySize),
                "Key size must be a positive number."
            );
        }
        _keySize = keySize;
    }

    public byte[] CreateKey() => RandomNumberGenerator.GetBytes(_keySize);

    public bool IsKeyValid(ReadOnlySpan<byte> key) => key.Length == _keySize;
}
