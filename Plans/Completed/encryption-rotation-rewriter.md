# Rewriting values from one provider to another

## Why

`ReEncrypt` rotates a **key** within one provider. There is no equivalent for rotating the
**provider**, and that is the case that has actually bitten a consumer: DocsToData held values
written as `AES-256-CBC-PKCS7` by an older default and needed them on `AES-256-GCM`.

The library had everything needed — `GetProviderForDecrypting` resolves the provider a value names,
and `Encrypt` writes with the current default — so the migration was about forty lines. But every
consumer who does this writes those forty lines themselves, and the most important of them is the
one most easily left out: reading the new value back before it replaces the old one. Get that wrong
and the row is destroyed, because the old value was the only copy.

## Shape

```csharp
var rewriter = new SymmetricEncryptionRewriter(factory, SymmetricEncryptionConstants.AES_GCM_CODE);
var updated = rewriter.Rewrite(storedValue, keyStore);
```

Four decisions, each with a reason:

- **Takes the key store, not the key.** Every other operation in this library takes an
  `ISymmetricKeyStoreProvider`, and since `294d72c` ("Move key material off strings and onto bytes")
  key lifetime deliberately belongs to the store. A type holding raw key material for its own
  lifetime would reintroduce exactly what that commit removed.
- **Returns the input unchanged when the value already names the target provider.** This makes a
  migration idempotent, makes a half-finished run safe to repeat, and removes the caller's need to
  compare provider names at all.
- **Verifies before returning.** Decrypt the rewritten value and compare against the plaintext;
  throw if they differ. This is the step a hand-rolled migration omits, and the one whose absence
  is unrecoverable.
- **Does not touch storage.** It maps one string to another. Which rows and columns hold encrypted
  values is the consuming application's knowledge, not something this library can stub without
  guessing.

## Also

- **`AsymmetricEncryptionRewriter`**, the same shape. Hashing already has its equivalent in
  `NeedsRehash` plus upgrade-on-verify; symmetric and asymmetric encryption have nothing.
- **Document `ProviderName`.** It appears in no doc file. Without it the obvious way to ask "what
  wrote this value" is to slice the string at the first colon, which is what the DocsToData
  migration did — hand-parsing a format the library already parses, in the one place a format change
  would silently break callers.

## Documentation: an encryption rotation guide

A prominent `Docs/encryption-rotation.md`, linked from `README.md` and `Docs/index.md` beside the
existing topics rather than buried in `symmetric-encryption.md`. Rotation is a thing people come
looking for under its own name, usually while something is broken.

It should answer, in this order:

1. **Which rotation is this?** Key, or provider. They are different operations with different tools
   (`ReEncrypt` versus `Rewrite`), and conflating them is how someone reaches for the wrong one. Say
   plainly that `ReEncrypt` keeps the provider and changes the key version.
2. **How to tell what a stored value currently uses** — `GetProviderForDecrypting(value).ProviderName`,
   not string surgery on the `providerName:keyVersion:base64Cipher` format.
3. **A worked migration**: enumerate rows, `Rewrite`, write back, one transaction, re-runnable. Say
   that a partly migrated database is worse than either end state, so the whole run commits or none
   of it does.
4. **That old values keep working without any migration**, because decryption resolves the provider
   from the value. Rotation is for retiring an old algorithm deliberately, not for restoring access.
   Anyone reading this guide during an outage is probably in the wrong place, and should be told so
   early.
5. **What the library does not do**: it does not know which of your columns are encrypted, and it
   will not find them for you.

Worth including the failure mode that produced this plan, because it is the thing a reader needs to
recognise: a value written by one provider and decrypted by another fails as
`AuthenticationTagMismatchException`, which looks exactly like a wrong key and sends the
investigation after the key rather than the algorithm.

## Tests

- A value written by a non-default provider is rewritten to the default and reads back.
- Rewriting an already-current value returns it unchanged, byte for byte, and does not re-encrypt
  (a fresh encryption would produce a different nonce, so this is observable).
- A key store is reusable across a long run — many values through one store, which is already true
  and worth pinning so it stays true.
- Round-trip verification fails loudly: force a mismatch and confirm it throws rather than returning
  a value that cannot be decrypted.

## Status

Implemented in 3.1.0.

- `SymmetricEncryptionRewriter` and `AsymmetricEncryptionRewriter`, both taking the key store,
  returning the input unchanged when it already names the target, and verifying the rewrite reads
  back before returning it.
- Target provider is resolved in the constructor rather than per call, so an unknown code fails
  where the stack points at configuration instead of at one row of a migration.
- `Docs/encryption-rotation.md`, linked from `README.md` and `Docs/index.md`. Opens by saying that
  old values keep working and that rotation is not a repair step, since anyone arriving mid-outage
  is in the wrong place.
- `ProviderName` documented in `Docs/provider-factories.md` with the "ask the factory, do not slice
  the string" example.
- Six tests, including the one that matters most: a provider that encrypts to something unreadable
  makes `Rewrite` throw rather than return a value that would overwrite the only copy.

One deviation worth noting: the plan's test list said to assert the unchanged-value case is not
re-encrypted. That is asserted through string equality rather than reference equality - a fresh
encryption produces a different nonce, so an identical string already proves no encryption
happened, and documenting `ReferenceEquals` as the check would be fragile advice for consumers
writing the same loop.
