using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Hashing.Providers;

public sealed class Pbkdf2HashProvider : IHashProvider
{
    public const int DEFAULT_ITERATIONS = 600_000;

    private const int SALT_SIZE = 16;
    private const int HASH_SIZE = 32;
    private const int EXPECTED_PART_COUNT = 4;

    private readonly int _iterations;

    public Pbkdf2HashProvider()
        : this(DEFAULT_ITERATIONS) { }

    public Pbkdf2HashProvider(int iterations)
    {
        if (iterations < 1)
        {
            throw new HashException("Iterations must be a positive number")
            {
                Reason = HashException.ErrorReason.InvalidFormat,
            };
        }
        _iterations = iterations;
    }

    public string ProviderName => HashConstants.PBKDF2_SHA256_CODE;

    public string ProviderDescription =>
        "PBKDF2-HMAC-SHA256 password hashing with a tunable work factor. A 16-byte random salt is "
        + "generated per operation. Output format: {ProviderName}:{iterations}:{Base64(salt)}:"
        + "{Base64(hash)}. The iteration count is stored per hash so it can be raised over time.";

    public string Hash(string value)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));

        var salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
        var hash = Derive(value, salt, _iterations);

        return $"{ProviderName}:{_iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    public bool Verify(string value, string hash)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));
        ArgumentNullException.ThrowIfNull(hash, nameof(hash));

        if (!TryParse(hash, out var iterations, out var salt, out var expected))
        {
            return false;
        }

        var actual = Derive(value, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public bool NeedsRehash(string hash) =>
        !TryParse(hash, out var iterations, out _, out _) || iterations < _iterations;

    private static byte[] Derive(string value, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(value),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HASH_SIZE
        );

    private bool TryParse(string hash, out int iterations, out byte[] salt, out byte[] expected)
    {
        iterations = 0;
        salt = [];
        expected = [];

        var parts = hash.Split(':');
        if (parts.Length != EXPECTED_PART_COUNT || parts[0] != ProviderName)
        {
            return false;
        }

        if (!int.TryParse(parts[1], out iterations) || iterations < 1)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length > 0 && expected.Length > 0;
    }
}
