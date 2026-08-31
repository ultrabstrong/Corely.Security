using System.Security.Cryptography;
using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.Signature.Providers;

public abstract class AsymmetricSignatureProviderBase : IAsymmetricSignatureProvider
{
    public string ProviderName { get; }

    public virtual string ProviderDescription => GetType().Name;

    // The name is supplied by the derived constructor rather than read from an abstract
    // property. Calling a virtual member from a base constructor observes the derived type
    // before its fields are assigned, so a name computed from constructor arguments was
    // either half-formed or null at the moment it was validated.
    protected AsymmetricSignatureProviderBase(string providerName)
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

    public string Sign(string data, IAsymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(data, nameof(data));
        var (_, privateKey) = keyStoreProvider.GetCurrentKeys();
        try
        {
            return SignInternal(data, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    public bool Verify(string data, string signature, IAsymmetricKeyStoreProvider keyStoreProvider)
    {
        ArgumentNullException.ThrowIfNull(data, nameof(data));
        ArgumentNullException.ThrowIfNull(signature, nameof(signature));
        var (publicKey, privateKey) = keyStoreProvider.GetCurrentKeys();
        CryptographicOperations.ZeroMemory(privateKey);
        return VerifyInternal(data, signature, publicKey);
    }

    public abstract IAsymmetricKeyProvider GetAsymmetricKeyProvider();

    public abstract SigningCredentials GetSigningCredentials(ReadOnlySpan<byte> key, bool isKeyPrivate);

    protected abstract string SignInternal(string value, ReadOnlySpan<byte> privateKey);

    protected abstract bool VerifyInternal(string value, string signature, ReadOnlySpan<byte> publicKey);
}
