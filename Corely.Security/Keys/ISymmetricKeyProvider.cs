namespace Corely.Security.Keys;

public interface ISymmetricKeyProvider
{
    byte[] CreateKey();

    bool IsKeyValid(ReadOnlySpan<byte> key);
}
