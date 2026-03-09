# Hashing

Purpose: Produce salted hashes with provider identification.

Default providers:
- SHA256 Salted (`"SHA256-Salted"`)
- SHA512 Salted (`"SHA512-Salted"`)

Factory usage:
```csharp
var factory = new HashProviderFactory(HashConstants.SALTED_SHA256_CODE);
var provider = factory.GetDefaultProvider();
var hash = provider.Hash("value");
var ok = provider.Verify("value", hash);
```
Resolve by encoded hash:
```csharp
var verifyProvider = factory.GetProviderToVerify(hash);
```
Format: `providerName:base64(salt+hash)` (salt bytes immediately followed by hash bytes, then Base64 encoded). Salt length is fixed at 16 bytes.

Add a custom hash provider:
```csharp
factory.AddProvider("DemoHash", new DemoHashProvider());
```
See demo: RunHashingDemo & RunAddCustomProvidersDemo.