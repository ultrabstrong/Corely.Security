using System.Security.Cryptography;
using System.Text;
using Corely.Security.Keys;

namespace Corely.Security.Encryption.Providers;

public sealed class AesGcmEncryptionProvider : SymmetricEncryptionProviderBase
{
    private const int NONCE_SIZE = 12;
    private const int TAG_SIZE = 16;

    public AesGcmEncryptionProvider()
        : base(SymmetricEncryptionConstants.AES_GCM_CODE) { }

    public override string ProviderDescription =>
        "AES-256-GCM authenticated encryption. A 12-byte nonce is randomly generated per operation "
        + "and prepended along with the 16-byte authentication tag. Output format: "
        + "Base64([nonce | tag | ciphertext]). Keys are Base64-encoded. Tampering is detected on "
        + "decryption.";

    private readonly AesKeyProvider _aesKeyProvider = new();

    protected override string EncryptInternal(string value, string key)
    {
        var keyBytes = Convert.FromBase64String(key);
        var plaintext = Encoding.UTF8.GetBytes(value);

        var nonce = RandomNumberGenerator.GetBytes(NONCE_SIZE);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TAG_SIZE];

        try
        {
            using var aesGcm = new AesGcm(keyBytes, TAG_SIZE);
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }

        var output = new byte[NONCE_SIZE + TAG_SIZE + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, output, 0, NONCE_SIZE);
        Buffer.BlockCopy(tag, 0, output, NONCE_SIZE, TAG_SIZE);
        Buffer.BlockCopy(ciphertext, 0, output, NONCE_SIZE + TAG_SIZE, ciphertext.Length);

        return Convert.ToBase64String(output);
    }

    protected override string DecryptInternal(string value, string key)
    {
        var keyBytes = Convert.FromBase64String(key);
        var input = Convert.FromBase64String(value);

        if (input.Length < NONCE_SIZE + TAG_SIZE)
        {
            throw new EncryptionException("Encrypted value is too short to contain a nonce and tag")
            {
                Reason = EncryptionException.ErrorReason.InvalidFormat,
            };
        }

        var nonce = input[..NONCE_SIZE];
        var tag = input[NONCE_SIZE..(NONCE_SIZE + TAG_SIZE)];
        var ciphertext = input[(NONCE_SIZE + TAG_SIZE)..];
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aesGcm = new AesGcm(keyBytes, TAG_SIZE);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public override ISymmetricKeyProvider GetSymmetricKeyProvider() => _aesKeyProvider;
}
