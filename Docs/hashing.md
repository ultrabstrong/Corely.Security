# Hashing

Purpose: Produce salted hashes with provider identification.

Default providers:
- PBKDF2 SHA256 (`"PBKDF2-SHA256"`) — use this for passwords
- SHA256 Salted (`"SHA256-Salted"`)
- SHA512 Salted (`"SHA512-Salted"`)

Factory usage:
```csharp
var factory = new HashProviderFactory(HashConstants.PBKDF2_SHA256_CODE);
var provider = factory.GetDefaultProvider();
var hash = provider.Hash("value");
var ok = provider.Verify("value", hash);
```
Resolve by encoded hash:
```csharp
var verifyProvider = factory.GetProviderToVerify(hash);
```
Format: `providerName:base64(salt+hash)` for the salted providers (salt bytes immediately followed by hash bytes, then Base64 encoded). Salt length is fixed at 16 bytes.

PBKDF2 differs — it stores its work factor per hash, so old hashes stay verifiable after the default is raised: `providerName:iterations:base64Salt:base64Hash`.

Work factor:
```csharp
var provider = new Pbkdf2HashProvider();                  // Pbkdf2HashProvider.DEFAULT_ITERATIONS
var cheaper = new Pbkdf2HashProvider(iterations: 1_000);  // tests only
```
`DEFAULT_ITERATIONS` meets the OWASP floor. Lower it in tests, never in production — the default costs real time per call, which is the point.

Upgrade stored hashes on use:
```csharp
if (provider.NeedsRehash(storedHash))
{
    storedHash = provider.Hash(plaintext);
}
```
`NeedsRehash` returns true for a hash from a different provider, or a PBKDF2 hash below the current iteration count. Call it after a successful verify, while the plaintext is still in hand — that migrates hashes as users return rather than needing a reset. The salted providers never need rehashing, so it returns false for them.

Add a custom hash provider:
```csharp
factory.AddProvider("DemoHash", new DemoHashProvider());
```
See demo: RunHashingDemo & RunAddCustomProvidersDemo.
