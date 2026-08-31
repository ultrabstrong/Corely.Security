# Key Stores

Versioned in-memory stores included:
- InMemorySymmetricKeyStoreProvider
- InMemoryAsymmetricKeyStoreProvider

They keep prior versions so re-encryption can migrate older payloads. No eviction or pruning is
performed.

`Get` and `GetCurrentKey` return `byte[]` copies. The caller owns what it receives; the provider
base classes zero the key after every operation, which is why the stores hand out copies rather
than their own arrays. Both stores accept Base64 `string` constructor overloads for keys that
arrive from configuration, and both expose `Clear()` to zero what they hold.

`FileSymmetricKeyStoreProvider` and `FileAsymmetricKeyStoreProvider` hold exactly one key (or
key pair) at version 1. `Get` throws `KeyStoreException` for any other version rather than
returning the only key it has.

Production note: These in-memory stores are for demo/runtime rotation only—not durable storage. Persist real keys in a managed KMS / key vault and hydrate a custom store implementation at startup.

Symmetric example:
```csharp
var p = factory.GetDefaultProvider();
var kp = p.GetSymmetricKeyProvider();
var store = new InMemorySymmetricKeyStoreProvider(kp.CreateKey()); // v1
var c = p.Encrypt("data", store);
store.Add(kp.CreateKey()); // v2
var migrated = p.ReEncrypt(c, store);
```
Asymmetric example:
```csharp
var p = factory.GetDefaultProvider();
var kp = p.GetAsymmetricKeyProvider();
var (pub, priv) = kp.CreateKeys();
var store = new InMemoryAsymmetricKeyStoreProvider(pub, priv); // v1
var c = p.Encrypt("data", store);
(var pub2, var priv2) = kp.CreateKeys();
store.Add(pub2, priv2); // v2
var migrated = p.ReEncrypt(c, store);
```
Demos: RunKeyStoreProvidersDemo, rotation inside encryption/signature demos.