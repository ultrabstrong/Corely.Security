# Key Stores

Versioned in-memory stores included:
- InMemorySymmetricKeyStoreProvider
- InMemoryAsymmetricKeyStoreProvider

They keep prior versions so re-encryption can migrate older payloads. No eviction or pruning is performed.

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