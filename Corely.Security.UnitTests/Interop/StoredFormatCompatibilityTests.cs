using Corely.Security.Encryption;
using Corely.Security.Encryption.Providers;
using Corely.Security.Hashing;
using Corely.Security.Hashing.Providers;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.Interop;

// Round-trip tests encrypt and decrypt with the same code in the same process, so they stay green
// through any change to the stored format. Consumers do not: Corely.IAM writes these strings to
// SQL and reads them back months later, under a newer version of this library. The literals below
// are the formats as shipped. A failure here means previously stored credentials and encrypted
// values have become unreadable, which no round-trip test can detect.
//
// Asymmetric providers are absent deliberately - pinning RSA/ECDSA output means committing a
// private key, and these formats (PKCS#8, SubjectPublicKeyInfo, DER signatures) are defined
// outside this library rather than by it.
public class StoredFormatCompatibilityTests
{
    private const string KeyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string Plaintext = "corely-security-known-answer";

    [Fact]
    public void Pbkdf2_VerifiesAStoredHash()
    {
        const string stored =
            "PBKDF2-SHA256:1000:c2FsdA==:YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM=";

        Assert.True(new Pbkdf2HashProvider().Verify("password", stored));
    }

    [Fact]
    public void SaltedSha256_VerifiesAStoredHash()
    {
        const string stored =
            "SHA256-Salted:AAECAwQFBgcICQoLDA0ODwSokUdgDMK161gup2xzyFRD93uf0Xjmnj5PFfa5dZaC";

        Assert.True(new Sha256SaltedHashProvider().Verify("password", stored));
    }

    [Fact]
    public void SaltedSha512_VerifiesAStoredHash()
    {
        const string stored =
            "SHA512-Salted:AAECAwQFBgcICQoLDA0OD5ivSmZX2q5RubuwGCaLSRAhlJgPlHY5nHH/UZ5J//Ne4OKo2q3grY6TDwZUFA5fTs6KYre5Ee+5zvMeBqES7VQ=";

        Assert.True(new Sha512SaltedHashProvider().Verify("password", stored));
    }

    [Fact]
    public void AesCbc_DecryptsAStoredValue()
    {
        const string stored =
            "AES-256-CBC-PKCS7:1:AAECAwQFBgcICQoLDA0ODyTz8Zk6QHQ70yjwTVyVVDZCHPhHRs071yrdA2uHx0Z+";

        var decrypted = new AesEncryptionProvider().Decrypt(
            stored,
            new InMemorySymmetricKeyStoreProvider(KeyBase64)
        );

        Assert.Equal(Plaintext, decrypted);
    }

    [Fact]
    public void AesGcm_DecryptsAStoredValue()
    {
        const string stored =
            "AES-256-GCM:1:AAECAwQFBgcICQoLM4uBKj7mnyk/+Gc9MaVvmCRtpH6pnO9o6CLi+didAUDouOhDnlY+EksQgPc=";

        var decrypted = new AesGcmEncryptionProvider().Decrypt(
            stored,
            new InMemorySymmetricKeyStoreProvider(KeyBase64)
        );

        Assert.Equal(Plaintext, decrypted);
    }

    // A stored value carries the key version it was written under. Reading it must select that
    // version rather than the current one, or every value written before a rotation breaks.
    [Fact]
    public void AesGcm_DecryptsWithTheKeyVersionRecordedInTheValue()
    {
        const string storedUnderVersion1 =
            "AES-256-GCM:1:AAECAwQFBgcICQoLM4uBKj7mnyk/+Gc9MaVvmCRtpH6pnO9o6CLi+didAUDouOhDnlY+EksQgPc=";

        var keyStore = new InMemorySymmetricKeyStoreProvider(KeyBase64);
        keyStore.Add(Convert.ToBase64String(new byte[32]));

        Assert.Equal(2, keyStore.GetCurrentVersion());
        Assert.Equal(
            Plaintext,
            new AesGcmEncryptionProvider().Decrypt(storedUnderVersion1, keyStore)
        );
    }

    // The envelope shape itself, asserted for values this suite cannot pin byte for byte.
    [Fact]
    public void HashProviders_EmitTheirDocumentedEnvelope()
    {
        var pbkdf2 = new Pbkdf2HashProvider(1000).Hash("password").Split(':');
        Assert.Equal(4, pbkdf2.Length);
        Assert.Equal(HashConstants.PBKDF2_SHA256_CODE, pbkdf2[0]);

        var salted = new Sha256SaltedHashProvider().Hash("password").Split(':');
        Assert.Equal(2, salted.Length);
        Assert.Equal(HashConstants.SALTED_SHA256_CODE, salted[0]);
    }

    [Fact]
    public void EncryptionProviders_EmitTheirDocumentedEnvelope()
    {
        var keyStore = new InMemorySymmetricKeyStoreProvider(KeyBase64);

        var gcm = new AesGcmEncryptionProvider().Encrypt(Plaintext, keyStore).Split(':');
        Assert.Equal(3, gcm.Length);
        Assert.Equal(SymmetricEncryptionConstants.AES_GCM_CODE, gcm[0]);
        Assert.Equal("1", gcm[1]);

        var cbc = new AesEncryptionProvider().Encrypt(Plaintext, keyStore).Split(':');
        Assert.Equal(3, cbc.Length);
        Assert.Equal(SymmetricEncryptionConstants.AES_CODE, cbc[0]);
        Assert.Equal("1", cbc[1]);
    }
}
