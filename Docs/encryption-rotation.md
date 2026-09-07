# Encryption Rotation

## If something is broken right now, you are probably in the wrong place

Values written by an older provider **keep working without any migration**. Decryption resolves the
provider from the stored value itself, so nothing has to be rewritten for old data to open.

Rotation is for retiring an algorithm or a key deliberately. It is not a repair step.

If a value has stopped decrypting, see [Diagnosing a failure](#diagnosing-a-failure) below.

## Which rotation is this?

Two different operations. Reaching for the wrong one is the most common mistake here.

| You want to change | Use | What it does |
|---|---|---|
| The **key**, same algorithm | `ReEncrypt` | Decrypts with the key version the value names, re-encrypts with the current key version. Provider is unchanged. |
| The **algorithm** (provider) | `Rewrite` | Decrypts with the provider the value names, re-encrypts with the target provider. |

```csharp
// Key rotation - same provider, newer key version
var rotated = provider.ReEncrypt(storedValue, keyStore);

// Provider rotation - e.g. AES-256-CBC-PKCS7 to AES-256-GCM
var rewriter = new SymmetricEncryptionRewriter(factory, SymmetricEncryptionConstants.AES_GCM_CODE);
var rewritten = rewriter.Rewrite(storedValue, keyStore);
```

`AsymmetricEncryptionRewriter` has the same shape for asymmetric values.

## What is this value using now?

Ask the factory. Do not slice the string.

```csharp
var providerName = factory.GetProviderForDecrypting(storedValue).ProviderName;
```

The stored format is `providerName:keyVersion:cipherBase64`, and it is tempting to split on the
first colon. That hand-parses a format the library already parses, in the one place a format change
would silently break callers.

## A worked migration

```csharp
var rewriter = new SymmetricEncryptionRewriter(factory, SymmetricEncryptionConstants.AES_GCM_CODE);

using var transaction = await connection.BeginTransactionAsync();

foreach (var row in await LoadRowsWithEncryptedValuesAsync())
{
    var rewritten = rewriter.Rewrite(row.EncryptedValue, keyStore);

    if (rewritten != row.EncryptedValue)
    {
        await UpdateEncryptedValueAsync(row.Id, rewritten);
    }
}

await transaction.CommitAsync();
```

Three properties worth relying on:

- **Re-runnable.** `Rewrite` returns the input unchanged when the value already uses the target
  provider, so a run that stops halfway can simply be run again.
- **Verified before it returns.** The rewritten value is decrypted and compared against the original
  plaintext. If it does not match, `Rewrite` throws and the original is untouched. This is the step
  a hand-rolled migration leaves out, and the only one whose absence is unrecoverable - once the
  rewritten value is written back, the original is gone.
- **All or nothing.** Run the whole migration in one transaction. A partly migrated database is
  worse than either end state, because you no longer know which rows are in which format without
  inspecting each one.

Run it against a restored backup first. The library can verify that a value it just produced reads
back; it cannot verify that your `UPDATE` wrote it to the right row.

## What this does not do

It maps one string to another. It does not know which of your tables and columns hold encrypted
values, and it will not find them for you - that is application knowledge, and guessing at it is
how a migration corrupts a column that only looked encrypted.

## Diagnosing a failure

A value written by one provider and decrypted by another fails as
`AuthenticationTagMismatchException` under AES-GCM. That is *also* what a wrong key looks like,
which is why this failure is worth recognising by name: the obvious reading sends you after the key,
and the key is usually fine.

Since 3.0.2 the exception says so directly, naming the provider that wrote the value and the one
reading it. On earlier versions, check the prefix on the stored value against the provider you are
decrypting with.

If they differ, you do not need a migration to recover - decrypt with
`factory.GetProviderForDecrypting(value)` and it will work. Migrate afterwards, deliberately, if you
still want to retire the old algorithm.
