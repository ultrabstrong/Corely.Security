using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Hashing.Providers;

/// <summary>
/// Single-round salted hashing.
///
/// Suitable for high-entropy values such as randomly generated tokens, where the input space is
/// already infeasible to search. NOT suitable for user-chosen passwords: a single round is fast by
/// design, and salting only defeats rainbow tables, not per-user brute force. Use
/// <see cref="Pbkdf2HashProvider"/> for passwords.
/// </summary>
public abstract class SaltedHashProviderBase : IHashProvider
{
    private const int SALT_SIZE = 16;
    private const int EXPECTED_PART_COUNT = 2;

    public abstract string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    public SaltedHashProviderBase()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ProviderName, nameof(ProviderName));
        if (ProviderName.Contains(':'))
        {
            throw new HashException($"Hash provider name cannot contain ':'")
            {
                Reason = HashException.ErrorReason.InvalidTypeCode
            };
        }
    }

    public string Hash(string value)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));

        var salt = CreateSalt();
        var saltedValue = CreateSaltedValue(salt, value);
        var hashedValue = HashInternal(saltedValue);
        return FormatHashedValue(salt, hashedValue);
    }

    private static byte[] CreateSalt() => RandomNumberGenerator.GetBytes(SALT_SIZE);

    private static byte[] CreateSaltedValue(byte[] salt, string value)
    {
        return [.. salt, .. Encoding.UTF8.GetBytes(value)];
    }

    private string FormatHashedValue(byte[] salt, byte[] hash)
    {
        var saltedHash = salt.Concat(hash).ToArray();
        var finalHash = Convert.ToBase64String(saltedHash);
        return $"{ProviderName}:{finalHash}";
    }

    public virtual bool Verify(string value, string originalHash)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));
        ArgumentNullException.ThrowIfNull(originalHash, nameof(originalHash));

        if (!TryParse(originalHash, out var salt, out var expectedHash))
        {
            return false;
        }

        var actualHash = HashInternal(CreateSaltedValue(salt, value));

        // Constant-time comparison of the digests. A short-circuiting comparison leaks how many
        // leading bytes matched.
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    /// <summary>
    /// Parses without throwing. A malformed or corrupted stored hash must produce a failed
    /// verification, never an exception escaping the authentication path - base64 decoding of a
    /// corrupted value would otherwise throw <see cref="FormatException"/>.
    /// </summary>
    private bool TryParse(string hash, out byte[] salt, out byte[] expectedHash)
    {
        salt = [];
        expectedHash = [];

        var parts = hash.Split(':');

        // Exact match rather than StartsWith: a provider name that is a prefix of another would
        // otherwise accept the wrong format.
        if (parts.Length != EXPECTED_PART_COUNT || parts[0] != ProviderName)
        {
            return false;
        }

        byte[] hashBytes;
        try
        {
            hashBytes = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (hashBytes.Length <= SALT_SIZE)
        {
            return false;
        }

        salt = hashBytes[..SALT_SIZE];
        expectedHash = hashBytes[SALT_SIZE..];
        return true;
    }

    protected abstract byte[] HashInternal(byte[] value);
}
