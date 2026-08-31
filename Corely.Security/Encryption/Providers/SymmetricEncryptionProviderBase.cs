using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption.Providers;

public abstract class SymmetricEncryptionProviderBase : ISymmetricEncryptionProvider
{
    public string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    // The name is supplied by the derived constructor rather than read from an abstract
    // property. Calling a virtual member from a base constructor observes the derived type
    // before its fields are assigned, so a name computed from constructor arguments was
    // either half-formed or null at the moment it was validated.
    protected SymmetricEncryptionProviderBase(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName, nameof(providerName));

        if (providerName.Contains(':'))
        {
            throw new EncryptionException($"Symmetric encryption provider name cannot contain ':'")
            {
                Reason = EncryptionException.ErrorReason.InvalidTypeCode
            };
        }

        ProviderName = providerName;
    }

    public string Encrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));
        var key = keyStoreProvider.GetCurrentKey();
        var encryptedValue = EncryptInternal(value, key);
        var version = keyStoreProvider.GetCurrentVersion();
        return FormatEncryptedValue(encryptedValue, version);
    }

    public string Decrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));
        (var encryptedValue, var version) = ValidateForKeyVersion(value);
        var key = keyStoreProvider.Get(version);
        return DecryptInternal(encryptedValue, key);
    }

    private (string, int) ValidateForKeyVersion(string value)
    {
        // The prefix is deliberately not checked against ProviderName. The factory already routed
        // this value here by that prefix, so re-checking it only forbids a provider from reading
        // values written under a name it has since moved on from - which is exactly what makes
        // renaming a provider impossible without stranding stored data.
        string[] parts = value.Split(':');

        if (parts.Length != 3
            || string.IsNullOrWhiteSpace(parts[0])
            || string.IsNullOrWhiteSpace(parts[2])
            || !int.TryParse(parts[1], out var keyVersion))
        {
            throw new EncryptionException("Value must be in format encryptionTypeCode:integer:encryptedValue")
            {
                Reason = EncryptionException.ErrorReason.InvalidFormat
            };
        }

        return (parts[2], keyVersion);
    }

    public string ReEncrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        (var encryptedValue, var version) = ValidateForKeyVersion(value);

        var decryptKey = keyStoreProvider.Get(version);
        var decrypted = DecryptInternal(encryptedValue, decryptKey);

        var encryptKey = keyStoreProvider.GetCurrentKey();
        var updatedEncryptedValue = EncryptInternal(decrypted, encryptKey);

        var currentVersion = keyStoreProvider.GetCurrentVersion();
        return FormatEncryptedValue(updatedEncryptedValue, currentVersion);
    }

    private string FormatEncryptedValue(string encryptedValue, int keyVersion)
    {
        return $"{ProviderName}:{keyVersion}:{encryptedValue}";
    }

    public string? RemoveEncodedEncryptionData(string value)
    {
        return value?.Split(':')?.Last();
    }

    public abstract ISymmetricKeyProvider GetSymmetricKeyProvider();

    protected abstract string DecryptInternal(string value, string key);

    protected abstract string EncryptInternal(string value, string key);
}
