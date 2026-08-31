# Symmetric Signatures

Default provider: HMAC SHA256 (`"HMAC-SHA256"`).

Sign / verify:
```csharp
var factory = new SymmetricSignatureProviderFactory(SymmetricSignatureConstants.HMAC_SHA256_CODE);
var provider = factory.GetDefaultProvider();
var keyStore = new InMemorySymmetricKeyStoreProvider(provider.GetSymmetricKeyProvider().CreateKey());
var sig = provider.Sign("payload", keyStore);
var ok = provider.Verify("payload", sig, keyStore);
```
Format: bare `base64Signature` - unlike encrypted values and hashes, signatures carry no
provider-name prefix and no key version. Note: HMAC SHA256 raw output is 32 bytes (Base64
length ~44 chars).

Rotation: add a new key; subsequent signatures use the latest key version. Existing signatures validate against stored version (the in-memory store keeps all versions).

Custom demo provider: `DemoSymmetricSignatureProvider` (provider name `"DemoSymSig"`).

Demos: RunSymmetricSignatureDemo, RunAddCustomProvidersDemo, SymmetricKeyStoreDemo.