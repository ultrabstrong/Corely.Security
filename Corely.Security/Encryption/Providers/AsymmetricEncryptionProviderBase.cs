using System.Security.Cryptography;
using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption.Providers;

public abstract class AsymmetricEncryptionProviderBase : IAsymmetricEncryptionProvider
{
    public string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    // The name is supplied by the derived constructor rather than read from an abstract
    // property. Calling a virtual member from a base constructor observes the derived type
    // before its fields are assigned, so a name computed from constructor arguments was
    // either half-formed or null at the moment it was validated.
    protected AsymmetricEncryptionProviderBase(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName, nameof(providerName));

        if (providerName.Contains(':'))
        {
            throw new EncryptionException($"Asymmetric encryption provider name cannot contain ':'")
            {
                Reason = EncryptionException.ErrorReason.InvalidTypeCode,
            };
        }

        ProviderName = providerName;
    }

    public string Encrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));
        var (publicKey, privateKey) = keyStoreProvider.GetCurrentKeys();
        CryptographicOperations.ZeroMemory(privateKey);
        var encryptedValue = EncryptInternal(value, publicKey);
        var version = keyStoreProvider.GetCurrentVersion();
        return FormatEncryptedValue(encryptedValue, version);
    }

    public string Decrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));
        (var encryptedValue, var version) = ValidateForKeyVersion(value);
        var (_, privateKey) = keyStoreProvider.Get(version);
        try
        {
            return DecryptInternal(encryptedValue, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private (string, int) ValidateForKeyVersion(string value)
    {
        // The prefix is deliberately not checked against ProviderName. The factory already routed
        // this value here by that prefix, so re-checking it only forbids a provider from reading
        // values written under a name it has since moved on from - which is exactly what makes
        // renaming a provider impossible without stranding stored data.
        string[] parts = value.Split(':');

        if (
            parts.Length != 3
            || string.IsNullOrWhiteSpace(parts[0])
            || string.IsNullOrWhiteSpace(parts[2])
            || !int.TryParse(parts[1], out var keyVersion)
        )
        {
            throw new EncryptionException(
                "Value must be in format encryptionTypeCode:integer:encryptedValue"
            )
            {
                Reason = EncryptionException.ErrorReason.InvalidFormat,
            };
        }

        return (parts[2], keyVersion);
    }

    public string ReEncrypt(string value, IAsymmetricKeyStoreProvider keyStoreProvider)
    {
        (var encryptedValue, var version) = ValidateForKeyVersion(value);

        var (_, privateKey) = keyStoreProvider.Get(version);
        var (publicKey, currentPrivateKey) = keyStoreProvider.GetCurrentKeys();
        CryptographicOperations.ZeroMemory(currentPrivateKey);

        string decrypted;
        try
        {
            decrypted = DecryptInternal(encryptedValue, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }

        var updatedEncryptedValue = EncryptInternal(decrypted, publicKey);

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

    public abstract IAsymmetricKeyProvider GetAsymmetricKeyProvider();

    protected abstract string DecryptInternal(string value, ReadOnlySpan<byte> privateKey);

    protected abstract string EncryptInternal(string value, ReadOnlySpan<byte> publicKey);
}
