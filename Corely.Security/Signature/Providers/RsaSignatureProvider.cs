using System.Security.Cryptography;
using System.Text;
using Corely.Security.Keys;
using Microsoft.IdentityModel.Tokens;

namespace Corely.Security.Signature.Providers;

public sealed class RsaSignatureProvider : AsymmetricSignatureProviderBase
{
    public override string ProviderDescription =>
        "RSA digital signature with PKCS#1 v1.5 padding. Keys use PKCS#8 (private) and SubjectPublicKeyInfo (public) format, Base64-encoded. Signature is Base64-encoded.";

    private readonly RsaKeyProvider _rsaKeyProvider = new();
    private readonly HashAlgorithmName _hashAlgorithm;

    public RsaSignatureProvider(HashAlgorithmName hashAlgorithm)
        : base($"RSA-PKCS1-{hashAlgorithm.Name}")
    {
        _hashAlgorithm = hashAlgorithm;
    }

    protected override string SignInternal(string value, ReadOnlySpan<byte> privateKey)
    {
        var dataToSign = Encoding.UTF8.GetBytes(value);

        using (var rsa = RSA.Create())
        {
            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            var signedBytes = rsa.SignData(dataToSign, _hashAlgorithm, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signedBytes);
        }
    }

    protected override bool VerifyInternal(
        string value,
        string signature,
        ReadOnlySpan<byte> publicKey
    )
    {
        var dataToVerify = Encoding.UTF8.GetBytes(value);
        var signatureBytes = Convert.FromBase64String(signature);

        using (var rsa = RSA.Create())
        {
            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            return rsa.VerifyData(
                dataToVerify,
                signatureBytes,
                _hashAlgorithm,
                RSASignaturePadding.Pkcs1
            );
        }
    }

    public override SigningCredentials GetSigningCredentials(
        ReadOnlySpan<byte> key,
        bool isKeyPrivate
    )
    {
        var rsa = RSA.Create();
        if (isKeyPrivate)
            rsa.ImportPkcs8PrivateKey(key, out _);
        else
            rsa.ImportSubjectPublicKeyInfo(key, out _);
        return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
    }

    public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => _rsaKeyProvider;
}
