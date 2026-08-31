using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.Signature.Providers;

public abstract class SymmetricSignatureProviderBase : ISymmetricSignatureProvider
{
    public abstract string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    public SymmetricSignatureProviderBase()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ProviderName, nameof(ProviderName));

        if (ProviderName.Contains(':'))
        {
            throw new SignatureException($"Signature provider name cannot contain ':'")
            {
                Reason = SignatureException.ErrorReason.InvalidTypeCode
            };
        }
    }

    public string Sign(string data, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(data, nameof(data));
        var key = keyStoreProvider.GetCurrentKey();
        return SignInternal(data, key);
    }

    public bool Verify(string data, string signature, ISymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(data, nameof(data));
        ArgumentNullException.ThrowIfNull(signature, nameof(signature));

        for (var version = keyStoreProvider.GetCurrentVersion(); version >= 1; version--)
        {
            string key;
            try
            {
                key = keyStoreProvider.Get(version);
            }
            catch (KeyStoreException)
            {
                continue;
            }

            if (VerifyInternal(data, signature, key))
            {
                return true;
            }
        }

        return false;
    }

    public abstract ISymmetricKeyProvider GetSymmetricKeyProvider();

    public abstract SigningCredentials GetSigningCredentials(string key);

    protected abstract string SignInternal(string value, string key);

    protected abstract bool VerifyInternal(string value, string signature, string key);
}
