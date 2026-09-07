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

Every provider exposes `ProviderName`, which is the same name written into the value's prefix. Use
it to find out what wrote a stored value, rather than splitting the string yourself:

```csharp
var writtenBy = factory.GetProviderForDecrypting(value).ProviderName;
```

Hand-parsing `providerName:keyVersion:cipherBase64` works until the format changes, and it is the
one place a format change would break callers silently.

To move stored values from one provider to another, see [Encryption Rotation](encryption-rotation.md).

Notes:
- Provider names must be non-empty and cannot contain ':' (validated at runtime)
- Factories are safe to register as singletons

Demo references: RunAddCustomProvidersDemo, provider name constants in each *Constants class.