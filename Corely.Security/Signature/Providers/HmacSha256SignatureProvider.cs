using Corely.Security.Keys;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Signature.Providers;

public sealed class HmacSha256SignatureProvider : SymmetricSignatureProviderBase
{
    public override string ProviderName => SymmetricSignatureConstants.HMAC_SHA256_CODE;

    public override string ProviderDescription =>
        "HMAC-SHA256 message authentication. Key is Base64-encoded. Signature output is Base64-encoded.";

    private readonly RandomKeyProvider _randomKeyProvider = new();

    protected override string SignInternal(string value, string key)
    {
        var keyBytes = Convert.FromBase64String(key);
        var dataToSign = Encoding.UTF8.GetBytes(value);

        try
        {
            using var hmac = new HMACSHA256(keyBytes);
            var signedBytes = hmac.ComputeHash(dataToSign);
            return Convert.ToBase64String(signedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    protected override bool VerifyInternal(string value, string signature, string key)
    {
        var keyBytes = Convert.FromBase64String(key);
        var dataToVerify = Encoding.UTF8.GetBytes(value);

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signature);
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            using var hmac = new HMACSHA256(keyBytes);
            var computedSignatureBytes = hmac.ComputeHash(dataToVerify);

            return CryptographicOperations.FixedTimeEquals(
                signatureBytes,
                computedSignatureBytes
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    public override SigningCredentials GetSigningCredentials(string key)
    {
        var securityKey = new SymmetricSecurityKey(Convert.FromBase64String(key));
        return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    }

    public override ISymmetricKeyProvider GetSymmetricKeyProvider() => _randomKeyProvider;
}
