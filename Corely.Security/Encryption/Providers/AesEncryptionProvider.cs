using Corely.Security.Keys;
using System.Security.Cryptography;

namespace Corely.Security.Encryption.Providers;

public sealed class AesEncryptionProvider : SymmetricEncryptionProviderBase
{
    public AesEncryptionProvider()
        : base(SymmetricEncryptionConstants.AES_CODE) { }

    public override string ProviderDescription =>
        "AES encryption using CBC mode with PKCS7 padding. A 16-byte IV is randomly generated per operation and prepended to the ciphertext. Output format: Base64([16-byte IV | ciphertext]). Keys are Base64-encoded.";

    private readonly AesKeyProvider _aesKeyProvider = new();

    protected override string EncryptInternal(string value, ReadOnlySpan<byte> key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key.ToArray();
            aes.GenerateIV();

            using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (MemoryStream msEncrypt = new())
            {
                // Prepend IV to the beginning of the encrypted string
                msEncrypt.Write(aes.IV, 0, aes.IV.Length);

                using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new(csEncrypt))
                {
                    swEncrypt.Write(value);
                }

                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    protected override string DecryptInternal(string value, ReadOnlySpan<byte> key)
    {
        using (Aes aes = Aes.Create())
        {
            byte[] fullCipher = Convert.FromBase64String(value);

            if (fullCipher.Length < aes.IV.Length)
            {
                throw new EncryptionException("Encrypted value is too short to contain an IV")
                {
                    Reason = EncryptionException.ErrorReason.InvalidFormat,
                };
            }

            byte[] iv = new byte[aes.IV.Length];
            byte[] cipherText = new byte[fullCipher.Length - iv.Length];

            // Extract IV from the beginning of the encrypted string
            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipherText, 0, cipherText.Length);

            aes.Key = key.ToArray();
            aes.IV = iv;

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (MemoryStream msDecrypt = new(cipherText))
            using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }
    }

    public override ISymmetricKeyProvider GetSymmetricKeyProvider() => _aesKeyProvider;
}
