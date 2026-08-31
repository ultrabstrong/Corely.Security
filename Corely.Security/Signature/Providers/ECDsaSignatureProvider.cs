using Corely.Security.Keys;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Signature.Providers;

public sealed class ECDsaSignatureProvider : AsymmetricSignatureProviderBase
{
    public override string ProviderDescription =>
        "ECDSA digital signature using the P-256 curve. Signatures are IEEE P1363 (the raw r and s "
        + "values concatenated, 64 bytes for P-256), Base64-encoded - not a DER sequence. Keys use "
        + "PKCS#8 (private) and SubjectPublicKeyInfo (public) format, Base64-encoded.";

    private readonly EcdsaKeyProvider _ecdsaKeyProvider = new();
    private readonly HashAlgorithmName _hashAlgorithm;

    public ECDsaSignatureProvider(HashAlgorithmName hashAlgorithm)
        : base($"ECDSA-{hashAlgorithm.Name}")
    {
        _hashAlgorithm = hashAlgorithm;
    }

    protected override string SignInternal(string value, string privateKey)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKey);
        var dataToSign = Encoding.UTF8.GetBytes(value);

        using (var ecdsa = ECDsa.Create())
        {
            ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
            var signedBytes = ecdsa.SignData(dataToSign, _hashAlgorithm);
            return Convert.ToBase64String(signedBytes);
        }
    }

    protected override bool VerifyInternal(string value, string signature, string publicKey)
    {
        var publicKeyBytes = Convert.FromBase64String(publicKey);
        var dataToVerify = Encoding.UTF8.GetBytes(value);
        var signatureBytes = Convert.FromBase64String(signature);

        using (var ecdsa = ECDsa.Create())
        {
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return ecdsa.VerifyData(dataToVerify, signatureBytes, _hashAlgorithm);
        }
    }

    public override SigningCredentials GetSigningCredentials(string key, bool isKeyPrivate)
    {
        var ecdsa = ECDsa.Create();
        if (isKeyPrivate)
            ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(key), out _);
        else
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(key), out _);
        return new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);
    }

    public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => _ecdsaKeyProvider;
}
