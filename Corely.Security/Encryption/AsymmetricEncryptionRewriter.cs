using Corely.Security.Encryption.Factories;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption;

/// <summary>
/// Rewrites a stored value from the provider that wrote it to a target provider.
/// </summary>
/// <remarks>
/// Rotates the provider. Use <c>ReEncrypt</c> to rotate the key while staying on one provider.
/// Older values stay readable without rewriting, so this is for retiring an algorithm, not for
/// recovering access.
/// </remarks>
public sealed class AsymmetricEncryptionRewriter
{
    private readonly IAsymmetricEncryptionProviderFactory _factory;
    private readonly string _targetProviderCode;

    public AsymmetricEncryptionRewriter(
        IAsymmetricEncryptionProviderFactory factory,
        string targetProviderCode
    )
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetProviderCode);

        // Fails at construction rather than mid-migration on an unknown code.
        _ = factory.GetProvider(targetProviderCode);

        _factory = factory;
        _targetProviderCode = targetProviderCode;
    }

    /// <summary>
    /// Returns <paramref name="value"/> re-encrypted under the target provider, or unchanged if it
    /// already names that provider. The rewritten value is decrypted and compared before being
    /// returned, so a value that cannot be read back never replaces the only copy of the original.
    /// </summary>
    public string Rewrite(string value, IAsymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        ArgumentNullException.ThrowIfNull(keyStoreProvider);

        var sourceProvider = _factory.GetProviderForDecrypting(value);

        // Makes a half-finished migration safe to re-run.
        if (sourceProvider.ProviderName == _targetProviderCode)
        {
            return value;
        }

        var plaintext = sourceProvider.Decrypt(value, keyStoreProvider);
        var rewritten = _factory
            .GetProvider(_targetProviderCode)
            .Encrypt(plaintext, keyStoreProvider);

        VerifyReadsBack(rewritten, plaintext, keyStoreProvider);

        return rewritten;
    }

    // Unrecoverable if skipped: once written back, the original is gone.
    private void VerifyReadsBack(
        string rewritten,
        string expected,
        IAsymmetricKeyStoreProvider keyStoreProvider
    )
    {
        string roundTripped;
        try
        {
            roundTripped = _factory
                .GetProviderForDecrypting(rewritten)
                .Decrypt(rewritten, keyStoreProvider);
        }
        catch (Exception ex)
        {
            throw new EncryptionException(
                "Rewritten value could not be decrypted. The original has not been modified.",
                ex
            )
            {
                Reason = EncryptionException.ErrorReason.InvalidFormat,
            };
        }

        if (roundTripped != expected)
        {
            throw new EncryptionException(
                "Rewritten value did not decrypt to the original plaintext. The original has not "
                    + "been modified."
            )
            {
                Reason = EncryptionException.ErrorReason.InvalidFormat,
            };
        }
    }
}
