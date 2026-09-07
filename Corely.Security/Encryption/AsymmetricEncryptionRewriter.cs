using Corely.Security.Encryption.Factories;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption;

/// <summary>
/// Rewrites a stored value from the provider that wrote it to a target provider.
/// </summary>
/// <remarks>
/// This rotates the <em>provider</em>. To rotate the <em>key</em> while staying on the same
/// provider, use <c>ReEncrypt</c> instead - they are different operations and reaching for the
/// wrong one is a common mistake.
/// <para>
/// Values written by an older provider keep working without any rewriting, because decryption
/// resolves the provider from the value itself. Rewriting is for retiring an algorithm
/// deliberately, not for restoring access to data that has stopped opening.
/// </para>
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

        // Resolved now rather than on each call so an unknown code fails at construction, where
        // the stack points at the caller's configuration instead of at one row of a migration.
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

        // Idempotent by design: a half-finished migration is safe to re-run, and the caller never
        // has to compare provider names.
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

    // The step a hand-rolled migration omits, and the only one whose absence is unrecoverable:
    // once the rewritten value is written back, the original is gone.
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
