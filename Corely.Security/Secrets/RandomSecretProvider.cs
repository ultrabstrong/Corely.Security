using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.Secrets;

public sealed class RandomSecretProvider : ISecretProvider
{
    public const int DEFAULT_SECRET_SIZE = 32;

    private readonly int _secretSize;

    public RandomSecretProvider(int secretSize = DEFAULT_SECRET_SIZE)
    {
        if (secretSize < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(secretSize),
                "Secret size must be a positive number."
            );
        }

        _secretSize = secretSize;
    }

    public string CreateSecret()
    {
        var secretBytes = RandomNumberGenerator.GetBytes(_secretSize);
        return Base64UrlEncoder.Encode(secretBytes);
    }

    public bool IsSecretValid(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            return false;
        }

        try
        {
            return Base64UrlEncoder.DecodeBytes(secret).Length == _secretSize;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
