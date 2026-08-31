using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.Signature.Providers;

public abstract class SymmetricSignatureProviderBase : ISymmetricSignatureProvider
{
    public string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    // The name is supplied by the derived constructor rather than read from an abstract
    // property. Calling a virtual member from a base constructor observes the derived type
    // before its fields are assigned, so a name computed from constructor arguments was
    // either half-formed or null at the moment it was validated.
    protected SymmetricSignatureProviderBase(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName, nameof(providerName));

        if (providerName.Contains(':'))
        {
            throw new SignatureException($"Signature provider name cannot contain ':'")
            {
                Reason = SignatureException.ErrorReason.InvalidTypeCode
            };
        }

        ProviderName = providerName;
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
