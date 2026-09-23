using System.Security.Cryptography;
using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption.Providers;

public abstract class SymmetricEncryptionProviderBase : ISymmetricEncryptionProvider
{
    public string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    protected SymmetricEncryptionProviderBase(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName, nameof(providerName));

        if (providerName.Contains(':'))
        {
            throw new EncryptionException($"Symmetric encryption provider name cannot contain ':'")
            {
                Reason = EncryptionException.ErrorReason.InvalidTypeCode,
            };
        }

        ProviderName = providerName;
    }

    public string Encrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));
        var key = keyStoreProvider.GetCurrentKey();
        try
        {
            var encryptedValue = EncryptInternal(value, key);
            var version = keyStoreProvider.GetCurrentVersion();
            return FormatEncryptedValue(encryptedValue, version);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public string Decrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));
        (var encryptedValue, var version) = ValidateForKeyVersion(value);
        var key = keyStoreProvider.Get(version);
        try
        {
            return DecryptInternal(encryptedValue, key);
        }
        catch (CryptographicException ex) when (NamesADifferentProvider(value))
        {
            throw new EncryptionException(
                $"Value was encrypted with '{value.Split(':')[0]}' but is being decrypted with "
                    + $"'{ProviderName}'. Decrypt it with the provider that wrote it, or re-encrypt "
                    + "it under the current provider.",
                ex
            )
            {
                Reason = EncryptionException.ErrorReason.InvalidTypeCode,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private bool NamesADifferentProvider(string value) =>
        value.Split(':') is [var named, _, _] && named != ProviderName;

    private (string, int) ValidateForKeyVersion(string value)
    {
        // Prefix not checked against ProviderName: the factory routed by it, and checking would block renames.
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

    public string ReEncrypt(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        (var encryptedValue, var version) = ValidateForKeyVersion(value);

        var decryptKey = keyStoreProvider.Get(version);
        var encryptKey = keyStoreProvider.GetCurrentKey();
        try
        {
            var decrypted = DecryptInternal(encryptedValue, decryptKey);
            var updatedEncryptedValue = EncryptInternal(decrypted, encryptKey);
            var currentVersion = keyStoreProvider.GetCurrentVersion();
            return FormatEncryptedValue(updatedEncryptedValue, currentVersion);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decryptKey);
            CryptographicOperations.ZeroMemory(encryptKey);
        }
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

    protected abstract string DecryptInternal(string value, ReadOnlySpan<byte> key);

    protected abstract string EncryptInternal(string value, ReadOnlySpan<byte> key);
}
