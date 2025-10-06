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
factory.AddProvider("99", new DemoSymmetricEncryptionProvider());
```
Update existing provider:
```csharp
factory.UpdateProvider("99", new DemoSymmetricEncryptionProvider());
```
Lookup:
```csharp
var prov = factory.GetProvider("00");
var list = factory.ListProviders();
```
Auto resolution (verification / decryption):
- Hash: `GetProviderToVerify(hash)`
- Symmetric encryption: `GetProviderForDecrypting(value)`
- Asymmetric encryption: `GetProviderForDecrypting(value)`
- Symmetric signature: `GetProviderForVerifying(value)`
- Asymmetric signature: `GetProviderForVerifying(value)`

Notes:
- Type codes must be non-empty and cannot contain ':' (validated at runtime)
- Factories are safe to register as singletons

Demo references: RunAddCustomProvidersDemo, provider code constants in each *Constants class.