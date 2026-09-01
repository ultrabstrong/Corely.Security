using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Hashing.Providers;

public abstract class SaltedHashProviderBase : IHashProvider
{
    private const int SALT_SIZE = 16;
    private const int EXPECTED_PART_COUNT = 2;

    public string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    // The name is supplied by the derived constructor rather than read from an abstract
    // property. Calling a virtual member from a base constructor observes the derived type
    // before its fields are assigned, so a name computed from constructor arguments was
    // either half-formed or null at the moment it was validated.
    protected SaltedHashProviderBase(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName, nameof(providerName));

        if (providerName.Contains(':'))
        {
            throw new HashException($"Hash provider name cannot contain ':'")
            {
                Reason = HashException.ErrorReason.InvalidTypeCode,
            };
        }

        ProviderName = providerName;
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
