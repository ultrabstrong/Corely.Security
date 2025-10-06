# Asymmetric Signatures

Default providers:
- ECDSA SHA256 (`"00"`)
- RSA SHA256 (`"01"`)

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
Format: `sigTypeCode:base64Signature`. Note: ECDSA signature length varies (DER encoded); RSA signature length reflects key modulus size.

Custom demo provider: `DemoAsymmetricSignatureProvider` (code `"96"`).

See demos: RunAsymmetricSignatureDemo, RunAddCustomProvidersDemo, AsymmetricKeyStoreDemo.