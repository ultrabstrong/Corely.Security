using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Hashing.Providers;

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
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    private bool TryParse(string hash, out byte[] salt, out byte[] expectedHash)
    {
        salt = [];
        expectedHash = [];

        var parts = hash.Split(':');
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
