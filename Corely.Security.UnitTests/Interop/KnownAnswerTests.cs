using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Hashing;
using Corely.Security.Hashing.Providers;
using Corely.Security.KeyStore;
using Corely.Security.Signature.Providers;

namespace Corely.Security.UnitTests.Interop;

// Every other test in this suite is a round trip: hash then verify, encrypt then decrypt. That
// proves the code agrees with itself, which it would continue to do if a provider silently
// implemented the wrong algorithm. These assert against values published by the standards bodies
// and reproduced with an implementation outside .NET, so they fail if the primitive underneath
// stops being the primitive the provider name claims.
public class KnownAnswerTests
{
    // RFC 8018 PBKDF2 with HMAC-SHA256, dkLen 32. The salt and derived key are spliced into the
    // provider's own storage format so Verify exercises the real parsing and derivation path.
    [Theory]
    [InlineData(1, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=")]
    [InlineData(2, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM=")]
    [InlineData(4096, "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o=")]
    public void Pbkdf2_MatchesPublishedVectors(int iterations, string expectedDerivedKey)
    {
        const string saltBase64 = "c2FsdA==";

        var hash =
            $"{HashConstants.PBKDF2_SHA256_CODE}:{iterations}:{saltBase64}:{expectedDerivedKey}";

        Assert.True(new Pbkdf2HashProvider(iterations).Verify("password", hash));
    }

    [Fact]
    public void Pbkdf2_RejectsTheVector_ForTheWrongPassword()
    {
        var hash =
            $"{HashConstants.PBKDF2_SHA256_CODE}:1:c2FsdA==:Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=";

        Assert.False(new Pbkdf2HashProvider(1).Verify("Password", hash));
    }

    // The salted providers hash salt || value and store Base64(salt || digest).
    [Fact]
    public void SaltedSha256_MatchesAnIndependentlyComputedDigest()
    {
        const string saltAndDigest =
            "AAECAwQFBgcICQoLDA0ODwSokUdgDMK161gup2xzyFRD93uf0Xjmnj5PFfa5dZaC";

        var hash = $"{HashConstants.SALTED_SHA256_CODE}:{saltAndDigest}";

        Assert.True(new Sha256SaltedHashProvider().Verify("password", hash));
    }

    [Fact]
    public void SaltedSha512_MatchesAnIndependentlyComputedDigest()
    {
        const string saltAndDigest =
            "AAECAwQFBgcICQoLDA0OD5ivSmZX2q5RubuwGCaLSRAhlJgPlHY5nHH/UZ5J//Ne4OKo2q3grY6TDwZUFA5fTs6KYre5Ee+5zvMeBqES7VQ=";

        var hash = $"{HashConstants.SALTED_SHA512_CODE}:{saltAndDigest}";

        Assert.True(new Sha512SaltedHashProvider().Verify("password", hash));
    }

    // RFC 4231 HMAC-SHA256 test cases 1 and 2.
    [Theory]
    [InlineData(
        "CwsLCwsLCwsLCwsLCwsLCwsLCws=",
        "Hi There",
        "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
    )]
    [InlineData(
        "SmVmZQ==",
        "what do ya want for nothing?",
        "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM="
    )]
    public void HmacSha256_MatchesRfc4231(string keyBase64, string data, string expectedSignature)
    {
        var keyStore = new InMemorySymmetricKeyStoreProvider(keyBase64);
        var provider = new HmacSha256SignatureProvider();

        Assert.Equal(expectedSignature, provider.Sign(data, keyStore));
        Assert.True(provider.Verify(data, expectedSignature, keyStore));
    }

    // Produced by a non-.NET AES-GCM implementation, then laid out in the order this provider
    // writes: nonce | tag | ciphertext. A change to that ordering fails here rather than silently
    // making every previously encrypted value undecryptable.
    [Fact]
    public void AesGcm_DecryptsAnIndependentlyProducedCiphertext()
    {
        const string keyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        const string payload =
            "AAECAwQFBgcICQoLM4uBKj7mnyk/+Gc9MaVvmCRtpH6pnO9o6CLi+didAUDouOhDnlY+EksQgPc=";

        var encrypted = $"{SymmetricEncryptionConstants.AES_GCM_CODE}:1:{payload}";
        var keyStore = new InMemorySymmetricKeyStoreProvider(keyBase64);

        var decrypted = new AesGcmEncryptionProvider().Decrypt(encrypted, keyStore);

        Assert.Equal("corely-security-known-answer", decrypted);
    }

    [Fact]
    public void AesGcm_RejectsATamperedTag()
    {
        const string keyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        var payload = Convert.FromBase64String(
            "AAECAwQFBgcICQoLM4uBKj7mnyk/+Gc9MaVvmCRtpH6pnO9o6CLi+didAUDouOhDnlY+EksQgPc="
        );
        payload[12] ^= 0xFF;

        var encrypted =
            $"{SymmetricEncryptionConstants.AES_GCM_CODE}:1:{Convert.ToBase64String(payload)}";
        var keyStore = new InMemorySymmetricKeyStoreProvider(keyBase64);

        Assert.ThrowsAny<Exception>(() =>
            new AesGcmEncryptionProvider().Decrypt(encrypted, keyStore)
        );
    }
}
