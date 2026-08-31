# Migrating to Corely.Security 2.0

Everything here is a compile-time break except the last section, which is the one to read if you
have data written by 1.x.

## Keys are bytes, not Base64 strings

A `string` cannot be zeroed and survives in the managed heap until collected, so 1.x cleared a
derived copy of the key while the original sat in memory. Key material is now `byte[]` on the way
out and `ReadOnlySpan<byte>` on the way in, and never becomes a `string` inside the library.

| 1.x | 2.0 |
|-----|-----|
| `string CreateKey()` | `byte[] CreateKey()` |
| `(string, string) CreateKeys()` | `(byte[], byte[]) CreateKeys()` |
| `bool IsKeyValid(string)` | `bool IsKeyValid(ReadOnlySpan<byte>)` |
| `string Get(int)` / `GetCurrentKey()` | `byte[] Get(int)` / `GetCurrentKey()` |
| `(string, string) Get(int)` / `GetCurrentKeys()` | `(byte[], byte[]) Get(int)` / `GetCurrentKeys()` |
| `GetSigningCredentials(string, ...)` | `GetSigningCredentials(ReadOnlySpan<byte>, ...)` |

Most call sites do not change, because `CreateKey()` now feeds the key store directly:

```csharp
var keyStore = new InMemorySymmetricKeyStoreProvider(provider.GetSymmetricKeyProvider().CreateKey());
```

Where a key arrives Base64-encoded - configuration, an environment variable, a database column -
the in-memory stores keep `string` constructor overloads. That string is yours to manage; the
library will not hold it.

```csharp
var keyStore = new InMemorySymmetricKeyStoreProvider(config["Security:SystemKey"]);
```

You own any array a key store hands you. The provider base classes zero it after every operation,
which is why the stores return copies. Both in-memory stores also expose `Clear()`.

## Custom providers pass their name to the base constructor

`ProviderName` was an abstract property read by the base constructor, which observes a derived type
before its fields are assigned. It is now a get-only base property set from a constructor argument.

```csharp
// 1.x
class MyProvider : SaltedHashProviderBase
{
    public override string ProviderName => "MyProvider";
}

// 2.0
class MyProvider : SaltedHashProviderBase
{
    public MyProvider() : base("MyProvider") { }
}
```

Custom providers also take `ReadOnlySpan<byte>` for keys in `EncryptInternal`, `DecryptInternal`,
`SignInternal`, `VerifyInternal` and `GetSigningCredentials`. Drop the
`Convert.FromBase64String(key)` line - the bytes arrive decoded.

## File key stores reject unknown versions

`FileSymmetricKeyStoreProvider` and `FileAsymmetricKeyStoreProvider` hold one key at version 1 and
cannot rotate. `Get(version)` used to ignore its argument and return that key for any version, so a
value written under version 2 was decrypted with the version 1 key and failed with no indication
why. They now throw `KeyStoreException` with `ErrorReason.InvalidVersion`.

To override file reading in a test, mock `GetFileBytes` rather than `GetFileContents`.

## GetProviderForVerifying is gone

Both signature factories exposed a method that split its input on `:` and looked up part zero.
Signatures carry no prefix and Base64 never contains `:`, so it always looked up the entire
signature as a provider code and always threw. Resolve signature providers with `GetProvider` or
`GetDefaultProvider`.

## Provider names no longer claim key properties

A provider cannot know the key size or curve it will be handed - both come from the key store at
call time - so the names no longer assert them.

| 1.x | 2.0 |
|-----|-----|
| `RSA-2048-OAEP-SHA256` | `RSA-OAEP-SHA256` |
| `RSA-2048-PKCS1-SHA256` | `RSA-PKCS1-SHA256` |
| `ECDSA-P256-SHA256` | `ECDSA-SHA256` |

**The 1.x names stay registered as read aliases, so values encrypted by 1.x still decrypt.** The
name is the prefix on every encrypted value, and `GetProviderForDecrypting` resolves by that
prefix. New values are written under the new name. If you build factories yourself rather than
using the defaults, register the legacy name too:

```csharp
factory.AddProvider(AsymmetricEncryptionConstants.LEGACY_RSA_CODE, provider);
```

## ECDSA signatures are P1363, not DER

Unchanged behaviour, corrected documentation. `ECDsaSignatureProvider` always emitted IEEE P1363
(raw `r || s`, 64 bytes for P-256); it described itself as DER. If you hand these signatures to an
external verifier, configure it for P1363 - or convert. Nothing about existing signatures changed.

## Your stored data

Hashes, encrypted values and signatures written by 1.x all remain readable. The known-answer
vectors and stored-format fixtures in `Corely.Security.UnitTests/Interop` pin this, and they pass
unchanged across every 2.0 refactor.

The one exception is the file key store version check above: if you were relying on it returning
the only key for a version other than 1, that now throws - and it was silently giving you the
wrong key before.
