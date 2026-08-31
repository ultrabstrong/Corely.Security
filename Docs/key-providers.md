# Key Providers

Generate and validate cryptographic keys. Retrieved via providers (encryption / signature) so consumers rarely construct them directly.

Included key types (accessed indirectly):
- AES symmetric (for encryption)
- Random/HMAC symmetric (for HMAC signatures)
- RSA asymmetric (encryption & signatures)
- ECDSA asymmetric (signatures)

Example:
```csharp
var encFactory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
var encProvider = encFactory.GetDefaultProvider();
var symKey = encProvider.GetSymmetricKeyProvider().CreateKey();
```
Asymmetric:
```csharp
var sigFactory = new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE);
var sigProvider = sigFactory.GetDefaultProvider();
var (pub, priv) = sigProvider.GetAsymmetricKeyProvider().CreateKeys();
```
Validation helpers:
```csharp
var valid = encProvider.GetSymmetricKeyProvider().IsKeyValid(symKey);
```
Note: Keys are returned as `byte[]`. The caller owns the array and should zero it with
`CryptographicOperations.ZeroMemory` once it has been persisted. Key material is never
materialised as a `string` inside the library, because a string cannot be zeroed and
survives in the heap until collected. Where a key arrives Base64-encoded - configuration,
an environment variable, a database column - the in-memory key stores take a `string`
overload; that string is the caller's to manage.

Production note: For real deployments implement a custom key provider that sources material from a managed KMS / HSM / vault and plugs in via the existing provider interfaces (instead of in-memory demo providers).

See demos: RunKeyProvidersDemo and other encryption/signature demos.