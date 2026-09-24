using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;

namespace Corely.Security.KeyStore;

internal static class ReadOnlySpanExtensions
{
    extension(ReadOnlySpan<byte> utf8Base64)
    {
        public byte[] DecodedBase64Key()
        {
            var decoded = new byte[Base64.GetMaxDecodedFromUtf8Length(utf8Base64.Length)];

            var status = Base64.DecodeFromUtf8(utf8Base64, decoded, out _, out var written);
            if (status != OperationStatus.Done)
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw new KeyStoreException("Key file does not contain valid Base64.")
                {
                    Reason = KeyStoreException.ErrorReason.CurrentKeyNotFound,
                };
            }

            var key = decoded[..written];
            if (written != decoded.Length)
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
            return key;
        }
    }
}
