# Asymmetric Signatures

Default providers:
- ECDSA SHA256 (`"ECDSA-P256-SHA256"`)
- RSA SHA256 (`"RSA-2048-PKCS1-SHA256"`)

Sign / verify:
```csharp
var factory = new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE);
var provider = factory.GetDefaultProvider();
var kp = provider.GetAsymmetricKeyProvider();
var (pub, priv) = kp.CreateKeys();
var store = new InMemoryAsymmetricKeyStoreProvider(pub, priv);
var sig = provider.Sign("payload", store);
var ok = provider.Verify("payload", sig, store);
```
Format: bare `base64Signature` - unlike encrypted values and hashes, signatures carry no
provider-name prefix and no key version. Note: ECDSA signatures are IEEE P1363 (raw r || s,
64 bytes for P-256), **not** DER; RSA signature length reflects key modulus size.

Custom demo provider: `DemoAsymmetricSignatureProvider` (provider name `"DemoAsymSig"`).

See demos: RunAsymmetricSignatureDemo, RunAddCustomProvidersDemo, AsymmetricKeyStoreDemo.