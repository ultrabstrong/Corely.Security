using Corely.Security.Keys;
using System.Security.Cryptography;
using System.Text;

namespace Corely.Security.Encryption.Providers;

public sealed class RsaEncryptionProvider : AsymmetricEncryptionProviderBase
{
    public override string ProviderDescription =>
        $"RSA encryption with {PaddingName(_rsaEncryptionPadding)} padding. Keys use PKCS#8 "
        + "(private) and SubjectPublicKeyInfo (public) format, Base64-encoded. Output is "
        + "Base64-encoded.";

    private readonly RsaKeyProvider _rsaKeyProvider = new();
    private readonly RSAEncryptionPadding _rsaEncryptionPadding;

    public RsaEncryptionProvider(RSAEncryptionPadding rsaEncryptionPadding)
        : base($"RSA-{PaddingName(rsaEncryptionPadding)}")
    {
        _rsaEncryptionPadding = rsaEncryptionPadding;
    }

    // Mapped explicitly rather than through ToString(): this name is the prefix on every stored
    // value, so the OaepSHA256 default must keep rendering "OAEP-SHA256".
    private static string PaddingName(RSAEncryptionPadding padding) =>
        padding.Mode == RSAEncryptionPaddingMode.Oaep
            ? $"OAEP-{padding.OaepHashAlgorithm.Name}"
            : "PKCS1";

    protected override string DecryptInternal(string value, ReadOnlySpan<byte> privateKey)
    {
        var encryptedBytes = Convert.FromBase64String(value);

        using (var rsa = RSA.Create())
        {
            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            var decryptedBytes = rsa.Decrypt(encryptedBytes, _rsaEncryptionPadding);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }

    protected override string EncryptInternal(string value, ReadOnlySpan<byte> publicKey)
    {
        var dataToEncrypt = Encoding.UTF8.GetBytes(value);

        using (var rsa = RSA.Create())
        {
            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            var encryptedBytes = rsa.Encrypt(dataToEncrypt, _rsaEncryptionPadding);
            return Convert.ToBase64String(encryptedBytes);
        }
    }

    public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => _rsaKeyProvider;
}
