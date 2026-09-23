using Corely.Security.Encryption.Factories;
using Corely.Security.KeyStore;

namespace Corely.Security.Encryption;

public sealed class SymmetricEncryptionRewriter
{
    private readonly ISymmetricEncryptionProviderFactory _factory;
    private readonly string _targetProviderCode;

    public SymmetricEncryptionRewriter(
        ISymmetricEncryptionProviderFactory factory,
        string targetProviderCode
    )
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetProviderCode);

        _ = factory.GetProvider(targetProviderCode);

        _factory = factory;
        _targetProviderCode = targetProviderCode;
    }

    public string Rewrite(string value, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        ArgumentNullException.ThrowIfNull(keyStoreProvider);

        var sourceProvider = _factory.GetProviderForDecrypting(value);

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

    private void VerifyReadsBack(
        string rewritten,
        string expected,
        ISymmetricKeyStoreProvider keyStoreProvider
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
