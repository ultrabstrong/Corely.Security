using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Corely.Security.Signature.Providers;

namespace Corely.Security.UnitTests.Signature.Providers;

public class SymmetricSignatureHardeningTests
{
    private const string Data = "message-to-authenticate";

    private readonly HmacSha256SignatureProvider _provider = new();

    [Fact]
    public void Verify_Succeeds_AfterKeyRotation()
    {
        var keyStore = CreateKeyStore();
        var signature = _provider.Sign(Data, keyStore);

        keyStore.Add(new RandomKeyProviderProxy().CreateKey());

        Assert.True(
            _provider.Verify(Data, signature, keyStore),
            "A signature issued before rotation must still verify against the retired key."
        );
    }

    [Fact]
    public void Verify_Succeeds_WithTheCurrentKeyAfterRotation()
    {
        var keyStore = CreateKeyStore();
        keyStore.Add(new RandomKeyProviderProxy().CreateKey());

        var signature = _provider.Sign(Data, keyStore);

        Assert.True(_provider.Verify(Data, signature, keyStore));
    }

    [Fact]
    public void Verify_Fails_ForAKeyThatWasNeverInTheStore()
    {
        var signingStore = CreateKeyStore();
        var signature = _provider.Sign(Data, signingStore);

        var unrelatedStore = CreateKeyStore();

        Assert.False(_provider.Verify(Data, signature, unrelatedStore));
    }

    [Fact]
    public void Verify_Fails_WhenDataIsAltered()
    {
        var keyStore = CreateKeyStore();
        var signature = _provider.Sign(Data, keyStore);

        Assert.False(_provider.Verify(Data + "!", signature, keyStore));
    }

    [Fact]
    public void Verify_Fails_WhenSignatureIsAltered()
    {
        var keyStore = CreateKeyStore();
        var signature = _provider.Sign(Data, keyStore);

        var bytes = Convert.FromBase64String(signature);
        bytes[0] ^= 0xFF;

        Assert.False(_provider.Verify(Data, Convert.ToBase64String(bytes), keyStore));
    }

    [Theory]
    [InlineData("")]
    [InlineData("!!!not-base64!!!")]
    [InlineData("short")]
    public void Verify_ReturnsFalse_WithMalformedSignature(string signature)
    {
        var keyStore = CreateKeyStore();

        Assert.False(_provider.Verify(Data, signature, keyStore));
    }

    [Fact]
    public void Verify_ReturnsFalse_WithASignatureOfTheWrongLength()
    {
        var keyStore = CreateKeyStore();
        var tooShort = Convert.ToBase64String(new byte[16]);

        Assert.False(_provider.Verify(Data, tooShort, keyStore));
    }

    private static InMemorySymmetricKeyStoreProvider CreateKeyStore() =>
        new(new RandomKeyProviderProxy().CreateKey());

    private sealed class RandomKeyProviderProxy
    {
        public byte[] CreateKey() =>
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    }
}
