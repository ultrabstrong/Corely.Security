using Corely.Security.Keys;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Signature.Providers;

public sealed class HmacSha256SignatureProvider : SymmetricSignatureProviderBase
{
    public HmacSha256SignatureProvider()
        : base(SymmetricSignatureConstants.HMAC_SHA256_CODE) { }

    public override string ProviderDescription =>
        "HMAC-SHA256 message authentication. Key is Base64-encoded. Signature output is Base64-encoded.";

    private readonly RandomKeyProvider _randomKeyProvider = new();

    protected override string SignInternal(string value, ReadOnlySpan<byte> key)
    {
        var dataToSign = Encoding.UTF8.GetBytes(value);

        using var hmac = new HMACSHA256(key.ToArray());
        return Convert.ToBase64String(hmac.ComputeHash(dataToSign));
    }

    protected override bool VerifyInternal(string value, string signature, ReadOnlySpan<byte> key)
    {
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

        using var hmac = new HMACSHA256(key.ToArray());
        return CryptographicOperations.FixedTimeEquals(
            signatureBytes,
            hmac.ComputeHash(dataToVerify)
        );
    }

    public override SigningCredentials GetSigningCredentials(ReadOnlySpan<byte> key)
    {
        var securityKey = new SymmetricSecurityKey(key.ToArray());
        return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    }

    public override ISymmetricKeyProvider GetSymmetricKeyProvider() => _randomKeyProvider;
}
