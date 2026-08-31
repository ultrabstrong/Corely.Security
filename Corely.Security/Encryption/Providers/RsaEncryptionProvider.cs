using Corely.Security.Keys;
using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Encryption.Providers;

public sealed class RsaEncryptionProvider : AsymmetricEncryptionProviderBase
{
    // This name is the prefix on every stored value, so the mapping is explicit rather than
    // ToString(): OaepSHA256 must keep rendering "RSA-2048-OAEP-SHA256" or existing ciphertext
    // stops being readable.
    public override string ProviderName => $"RSA-2048-{PaddingName}";

    private string PaddingName
    {
        get
        {
            // AsymmetricEncryptionProviderBase validates ProviderName from its own constructor,
            // which runs before this field is assigned. The fallback is only ever observed during
            // that validation, never by a caller.
            if (_rsaEncryptionPadding is null)
            {
                return "OAEP-SHA256";
            }

            return _rsaEncryptionPadding.Mode == RSAEncryptionPaddingMode.Oaep
                ? $"OAEP-{_rsaEncryptionPadding.OaepHashAlgorithm.Name}"
                : "PKCS1";
        }
    }

    public override string ProviderDescription =>
        "RSA encryption with OAEP-SHA256 padding. Keys use PKCS#8 (private) and SubjectPublicKeyInfo (public) format, Base64-encoded. Output is Base64-encoded.";

    private readonly RsaKeyProvider _rsaKeyProvider = new();
    private readonly RSAEncryptionPadding _rsaEncryptionPadding;

    public RsaEncryptionProvider(RSAEncryptionPadding rsaEncryptionPadding)
    {
        _rsaEncryptionPadding = rsaEncryptionPadding;
    }

    protected override string DecryptInternal(string value, string privateKey)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKey);
        var encryptedBytes = Convert.FromBase64String(value);

        using (var rsa = RSA.Create())
        {
            rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
            var decryptedBytes = rsa.Decrypt(encryptedBytes, _rsaEncryptionPadding);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }

    protected override string EncryptInternal(string value, string publicKey)
    {
        var publicKeyBytes = Convert.FromBase64String(publicKey);
        var dataToEncrypt = Encoding.UTF8.GetBytes(value);

        using (var rsa = RSA.Create())
        {
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            var encryptedBytes = rsa.Encrypt(dataToEncrypt, _rsaEncryptionPadding);
            return Convert.ToBase64String(encryptedBytes);
        }
    }

    public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => _rsaKeyProvider;
}
