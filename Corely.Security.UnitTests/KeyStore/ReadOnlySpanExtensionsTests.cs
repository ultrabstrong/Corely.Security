using System.Text;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.KeyStore;

public class ReadOnlySpanExtensionsTests
{
    [Fact]
    public void DecodedBase64Key_ReturnsTheExactDecodedBytes()
    {
        byte[] key = [1, 2, 3, 4, 5];
        ReadOnlySpan<byte> encoded = Encoding.UTF8.GetBytes(Convert.ToBase64String(key));

        Assert.Equal(key, encoded.DecodedBase64Key());
    }

    [Fact]
    public void DecodedBase64Key_Throws_WhenNotBase64()
    {
        var ex = Assert.Throws<KeyStoreException>(() =>
        {
            ReadOnlySpan<byte> encoded = "not base64!"u8;
            encoded.DecodedBase64Key();
        });

        Assert.Equal(KeyStoreException.ErrorReason.CurrentKeyNotFound, ex.Reason);
    }
}
