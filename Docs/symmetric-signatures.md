# Symmetric Signatures

Default provider: HMAC SHA256 (`"00"`).

Sign / verify:
```csharp
var factory = new SymmetricSignatureProviderFactory(SymmetricSignatureConstants.HMAC_SHA256_CODE);
var provider = factory.GetDefaultProvider();
var keyStore = new InMemorySymmetricKeyStoreProvider(provider.GetSymmetricKeyProvider().CreateKey());
var sig = provider.Sign("payload", keyStore);
var ok = provider.Verify("payload", sig, keyStore);
```
Format: `sigTypeCode:base64Signature`. Note: HMAC SHA256 raw output is 32 bytes (Base64 length ~44 chars).

Rotation: add a new key; subsequent signatures use the latest key version. Existing signatures validate against stored version (the in-memory store keeps all versions).

Custom demo provider: `DemoSymmetricSignatureProvider` (code `"97"`).

Demos: RunSymmetricSignatureDemo, RunAddCustomProvidersDemo, SymmetricKeyStoreDemo.