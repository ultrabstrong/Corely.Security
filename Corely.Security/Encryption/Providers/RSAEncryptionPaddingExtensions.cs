using System.Security.Cryptography;

namespace Corely.Security.Encryption.Providers;

internal static class RSAEncryptionPaddingExtensions
{
    extension(RSAEncryptionPadding padding)
    {
        public string ShortName() =>
            padding.Mode == RSAEncryptionPaddingMode.Oaep
                ? $"OAEP-{padding.OaepHashAlgorithm.Name}"
                : "PKCS1";
    }
}
