using System.Security.Cryptography;
using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Corely.Security.Signature.Providers;

namespace Corely.Security.UnitTests.Interop;

// Verification needs only a public key, so these pin real cross-implementation vectors without
// any secret in the repository. The message and signature were produced outside .NET; if a
// provider's curve, padding scheme, hash algorithm, or signature encoding drifts from what its
// name advertises, verification of an externally produced signature stops working.
//
// A key pair generated inside the test would not do this. Signing and verifying with the same
// freshly generated key is a round trip, and a round trip passes through any change applied
// consistently to both halves - which is exactly how the AES-GCM layout mutation slipped past
// 154 existing tests.
public class AsymmetricKnownAnswerTests
{
    private const string Message = "corely-security-known-answer";

    private const string EcdsaPublicKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7FH1C9bnJiTB16IZcgHOlE3+14fV8MMVaexEXRjEw1Wp"
        + "Qdwp3dVQO+0ofsxbE03ip6y2Mtj6KIwccfq4sX8ktA==";

    // IEEE P1363 (raw r || s), which is what .NET's ECDsa.VerifyData consumes by default -
    // NOT the DER sequence that ProviderDescription advertises. See EcdsaSignatureFormat below.
    private const string EcdsaSignature =
        "YOB42XA/X3Amw+vKpst0QSOBSYjBDCl401/nPh4IZ8rmCueBVur2uMiywGnhf8s/zwjFgZ2FxtOnugZY"
        + "EcoZMg==";

    private const string RsaPublicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuXEEwss9OjbcPkx1D58ScQXBKzwT2g/dVmqY"
        + "oxVFg0QmaTWqRAGru9rg3y15leGnpieM193Qn2IgIzFNs1MoNQHF2884f9Z3z0WnDQwTeSvs2y8DbXbp"
        + "lY/iMVLCTrQ/TEywPdz1/6LSnnjgI/P64BRIQtant8hYL8jIkwVO3U0HaLuQB75iKbiM+K7vb83HFxBF"
        + "x/5cpMfzP2bTOiHhbhrrTu4Z3f5TfWwdimKf5+4WckjXRCI9K0t62qTOc6JmNp40526YtwjB4UwT5+79"
        + "U+AYnL/CHlmTu83I99AdBA8Ft2+G7Lmbo/YfAMe4BBXh+2Gh+eE4fGbZe1fNjofcRwIDAQAB";

    private const string RsaSignature =
        "HtRHatNB1nPTSUxZclAKTC/RD1REK3fvjybDZPoChAuHqjEA4B0aW8Nr1qmGy+cQjQ0Zuxgx2ZnTzOPa"
        + "nN7Qh/pcI4ekCVNGylqHh25bIYBBhUTnvZaOdLtIpOM9CxaIftU6POJ2/FcFBr9mWUvH1Oadn/MxrMqz"
        + "h3UKfQ9ehsp2yItDD4cu56hSvVH/xACkOJs6cQ7DCBMY60+qUSxjhL1I9a+W9+DR48K/cE3qHu2U9ZRk"
        + "5Z8UIn0aD8h+ZDQLGvHx6MfCcGZwNyATGcyh2gmjB7xpYpWIIh4s1/KCTD2cdpFKRhPkGtc9wykiiO4I"
        + "sNSFb1Hy5664jEqDthMhAA==";

    // Same message, signed by a different P-256 key. Guards against a verify path that returns
    // true without actually checking anything.
    private const string EcdsaSignatureFromAnotherKey =
        "EkfOB1P1vrHR/LCL6Yx8w6mrYnr6cXx1cWpP9AapCG1q2NHCsPWJOI5ZJ/7YPnrTjgMXZl4QiQsZB7WQ"
        + "Y0D9ZQ==";

    // The private key is never used on the verification path; the store requires one, so the
    // public key is passed in its place to keep secrets out of the repository.
    private static InMemoryAsymmetricKeyStoreProvider PublicOnlyStore(string publicKey) =>
        new(publicKey, publicKey);

    [Fact]
    public void Ecdsa_VerifiesAnExternallyProducedSignature()
    {
        var provider = new ECDsaSignatureProvider(HashAlgorithmName.SHA256);

        Assert.True(provider.Verify(Message, EcdsaSignature, PublicOnlyStore(EcdsaPublicKey)));
    }

    [Fact]
    public void Ecdsa_RejectsASignatureFromAnotherKey()
    {
        var provider = new ECDsaSignatureProvider(HashAlgorithmName.SHA256);

        Assert.False(
            provider.Verify(Message, EcdsaSignatureFromAnotherKey, PublicOnlyStore(EcdsaPublicKey))
        );
    }

    [Fact]
    public void Ecdsa_RejectsAModifiedMessage()
    {
        var provider = new ECDsaSignatureProvider(HashAlgorithmName.SHA256);

        Assert.False(
            provider.Verify(Message + "!", EcdsaSignature, PublicOnlyStore(EcdsaPublicKey))
        );
    }

    [Fact]
    public void Rsa_VerifiesAnExternallyProducedSignature()
    {
        var provider = new RsaSignatureProvider(HashAlgorithmName.SHA256);

        Assert.True(provider.Verify(Message, RsaSignature, PublicOnlyStore(RsaPublicKey)));
    }

    [Fact]
    public void Rsa_RejectsAModifiedMessage()
    {
        var provider = new RsaSignatureProvider(HashAlgorithmName.SHA256);

        Assert.False(provider.Verify(Message + "!", RsaSignature, PublicOnlyStore(RsaPublicKey)));
    }

    // The signature encoding is the thing that decides whether an external system can consume
    // these signatures at all, and nothing else in the suite pins it. P-256 P1363 is exactly
    // 64 bytes; a DER sequence for the same curve is 70-72 and starts with 0x30.
    [Fact]
    public void Ecdsa_EmitsP1363NotDer()
    {
        var keys = new EcdsaKeyProvider().CreateKeys();
        var provider = new ECDsaSignatureProvider(HashAlgorithmName.SHA256);

        var signature = Convert.FromBase64String(
            provider.Sign(
                Message,
                new InMemoryAsymmetricKeyStoreProvider(keys.PublicKey, keys.PrivateKey)
            )
        );

        Assert.Equal(64, signature.Length);
        Assert.NotEqual(0x30, signature[0]);
    }

    [Fact]
    public void Ecdsa_DescribesTheFormatItActuallyEmits()
    {
        var description = new ECDsaSignatureProvider(HashAlgorithmName.SHA256).ProviderDescription;

        Assert.Contains("P1363", description);
        Assert.DoesNotContain("DER format", description);
    }
}
