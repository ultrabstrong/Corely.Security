# Provider Factories & Custom Providers

Factories supply default implementations and allow registration of additional providers.

Factories:
- HashProviderFactory
- SymmetricEncryptionProviderFactory
- AsymmetricEncryptionProviderFactory
- SymmetricSignatureProviderFactory
- AsymmetricSignatureProviderFactory

Add custom provider:
```csharp
var factory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
factory.AddProvider("DemoSymEnc", new DemoSymmetricEncryptionProvider());
```
Update existing provider:
```csharp
factory.UpdateProvider("DemoSymEnc", new DemoSymmetricEncryptionProvider());
```
Lookup:
```csharp
var prov = factory.GetProvider("AES-256-CBC-PKCS7");
var list = factory.ListProviders();
```
Auto resolution (verification / decryption):
- Hash: `GetProviderToVerify(hash)`
- Symmetric encryption: `GetProviderForDecrypting(value)`
- Asymmetric encryption: `GetProviderForDecrypting(value)`
- Symmetric signature: `GetProviderForVerifying(value)`
- Asymmetric signature: `GetProviderForVerifying(value)`

Notes:
- Provider names must be non-empty and cannot contain ':' (validated at runtime)
- Factories are safe to register as singletons

Demo references: RunAddCustomProvidersDemo, provider name constants in each *Constants class.