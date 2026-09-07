# Encryption Rotation

Two different rotations. Values written by an older provider or key stay readable either way — decryption resolves both from the stored value — so rotation is for retiring an algorithm or key deliberately, not for restoring access.

| Rotate | Use | Effect |
|--------|-----|--------|
| Key | `ReEncrypt` | Same provider, current key version |
| Provider | `Rewrite` | Provider the value names → target provider |

Rotate a key:
```csharp
keyStore.Add(provider.GetSymmetricKeyProvider().CreateKey());
var rotated = provider.ReEncrypt(cipher, keyStore);
```

Rotate a provider:
```csharp
var rewriter = new SymmetricEncryptionRewriter(factory, SymmetricEncryptionConstants.AES_GCM_CODE);
var rewritten = rewriter.Rewrite(cipher, keyStore);
```

`AsymmetricEncryptionRewriter` takes `IAsymmetricKeyStoreProvider` and behaves the same.

`Rewrite` returns the input unchanged when it already names the target provider, so a migration is re-runnable. It decrypts the rewritten value and compares it against the original plaintext before returning, throwing rather than handing back a value that cannot be read — the original is the only copy until it is overwritten.

Migrate stored values:
```csharp
using var transaction = await connection.BeginTransactionAsync();

foreach (var row in await LoadRowsWithEncryptedValuesAsync())
{
    var rewritten = rewriter.Rewrite(row.EncryptedValue, keyStore);
    if (rewritten != row.EncryptedValue)
        await UpdateEncryptedValueAsync(row.Id, rewritten);
}

await transaction.CommitAsync();
```

Run the whole migration in one transaction — a partly migrated database is worse than either end state, because which rows are in which format is no longer knowable without inspecting each one.

Ask what wrote a value rather than parsing the prefix:
```csharp
var writtenBy = factory.GetProviderForDecrypting(value).ProviderName;
```

Note: the library maps one string to another. Which columns hold encrypted values is application knowledge — it will not find them for you.

Decrypting a value with a provider that did not write it throws `EncryptionException` naming both providers. Under AES-GCM the underlying failure is an authentication tag mismatch, which is also what a wrong key produces — check the provider before the key. No migration is needed to recover: `GetProviderForDecrypting` reads the value as-is.

Relevant demos: RunSymmetricEncryptionDemo, SymmetricKeyStoreDemo.
