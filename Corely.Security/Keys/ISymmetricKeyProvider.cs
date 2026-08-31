namespace Corely.Security.Keys;

public interface ISymmetricKeyProvider
{
    /// <summary>
    /// Creates a new key. The caller owns the returned array and should zero it with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/> once it has
    /// been persisted.
    /// </summary>
    byte[] CreateKey();

    bool IsKeyValid(ReadOnlySpan<byte> key);
}
