using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.Encryption.Providers;
using Corely.Security.Keys;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.Encryption;

public class SymmetricEncryptionRewriterTests
{
    private const string SOURCE_CODE = SymmetricEncryptionConstants.AES_CODE;
    private const string TARGET_CODE = SymmetricEncryptionConstants.AES_GCM_CODE;

    private readonly ISymmetricEncryptionProviderFactory _factory =
        new SymmetricEncryptionProviderFactory(TARGET_CODE);
    private readonly ISymmetricKeyStoreProvider _keyStore;
    private readonly SymmetricEncryptionRewriter _rewriter;

    public SymmetricEncryptionRewriterTests()
    {
        _keyStore = new InMemorySymmetricKeyStoreProvider(
            _factory.GetDefaultProvider().GetSymmetricKeyProvider().CreateKey()
        );
        _rewriter = new SymmetricEncryptionRewriter(_factory, TARGET_CODE);
    }

    private string EncryptWith(string providerCode, string plaintext) =>
        _factory.GetProvider(providerCode).Encrypt(plaintext, _keyStore);

    [Fact]
    public void Rewrite_MovesAValueToTheTargetProvider_AndItReadsBack()
    {
        const string plaintext = "value written by an older default";
        var original = EncryptWith(SOURCE_CODE, plaintext);

        var rewritten = _rewriter.Rewrite(original, _keyStore);

        Assert.StartsWith(TARGET_CODE, rewritten);
        Assert.Equal(
            plaintext,
            _factory.GetProviderForDecrypting(rewritten).Decrypt(rewritten, _keyStore)
        );
    }

    [Fact]
    public void Rewrite_ReturnsTheValueUnchanged_WhenItAlreadyUsesTheTargetProvider()
    {
        var alreadyCurrent = EncryptWith(TARGET_CODE, "already on the target");

        var rewritten = _rewriter.Rewrite(alreadyCurrent, _keyStore);

        // Reference equality of content matters: re-encrypting would produce a different nonce, so
        // an identical string proves no encryption happened and the migration is re-runnable.
        Assert.Equal(alreadyCurrent, rewritten);
    }

    [Fact]
    public void Rewrite_IsIdempotent_WhenRunTwice()
    {
        var original = EncryptWith(SOURCE_CODE, "run me twice");

        var once = _rewriter.Rewrite(original, _keyStore);
        var twice = _rewriter.Rewrite(once, _keyStore);

        Assert.Equal(once, twice);
    }

    [Fact]
    public void Rewrite_ReusesOneKeyStoreAcrossManyValues()
    {
        var originals = Enumerable
            .Range(0, 50)
            .Select(i => EncryptWith(SOURCE_CODE, $"value {i}"))
            .ToList();

        var rewritten = originals.Select(v => _rewriter.Rewrite(v, _keyStore)).ToList();

        for (var i = 0; i < originals.Count; i++)
        {
            Assert.Equal(
                $"value {i}",
                _factory.GetProviderForDecrypting(rewritten[i]).Decrypt(rewritten[i], _keyStore)
            );
        }
    }

    [Fact]
    public void Rewrite_Throws_WhenTheRewrittenValueDoesNotReadBack()
    {
        var factory = new SymmetricEncryptionProviderFactory(TARGET_CODE);
        factory.UpdateProvider(
            TARGET_CODE,
            new CorruptingEncryptionProvider(
                TARGET_CODE,
                _factory.GetDefaultProvider().GetSymmetricKeyProvider()
            )
        );
        var rewriter = new SymmetricEncryptionRewriter(factory, TARGET_CODE);

        var original = EncryptWith(SOURCE_CODE, "must not be silently destroyed");

        var ex = Assert.Throws<EncryptionException>(() => rewriter.Rewrite(original, _keyStore));

        Assert.Contains("original has not been modified", ex.Message);
    }

    [Fact]
    public void Constructor_Throws_WhenTheTargetProviderIsUnknown()
    {
        Assert.ThrowsAny<Exception>(() =>
            new SymmetricEncryptionRewriter(_factory, "not-a-real-provider")
        );
    }

    /// <summary>
    /// Encrypts to something that will not decrypt back to the original, standing in for any bug
    /// that would otherwise write an unreadable value over the only copy.
    /// </summary>
    private sealed class CorruptingEncryptionProvider(
        string providerName,
        ISymmetricKeyProvider keyProvider
    ) : SymmetricEncryptionProviderBase(providerName)
    {
        public override ISymmetricKeyProvider GetSymmetricKeyProvider() => keyProvider;

        protected override string EncryptInternal(string value, ReadOnlySpan<byte> key) =>
            Convert.ToBase64String("corrupted"u8);

        protected override string DecryptInternal(string value, ReadOnlySpan<byte> key) =>
            "not the original plaintext";
    }
}
