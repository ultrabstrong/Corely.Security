# Provider Display Name

## Summary

Crypto providers in Corely.Security use opaque numeric IDs (`"00"`, `"01"`) as their only
identifying property (`EncryptionTypeCode` / `SignatureTypeCode` / `HashTypeCode`). These codes
are ambiguous across contexts, meaningless to humans, and embedded in stored encrypted/hashed
output. This plan replaces them entirely with `ProviderName` — a human-readable, self-documenting
identifier that serves as both the factory lookup key and the display name.

## Current State

| Provider | Type Code Property | Value | Human Meaning |
|----------|-------------------|-------|---------------|
| `AesEncryptionProvider` | `EncryptionTypeCode` | `"00"` | AES |
| `RsaEncryptionProvider` | `EncryptionTypeCode` | `"00"` | RSA |
| `ECDsaSignatureProvider` | `SignatureTypeCode` | `"00"` | ECDSA-SHA256 |
| `RsaSignatureProvider` | `SignatureTypeCode` | `"01"` | RSA-SHA256 |
| `HmacSha256SignatureProvider` | `SignatureTypeCode` | `"00"` | HMAC-SHA256 |
| `Sha256SaltedHashProvider` | `HashTypeCode` | `"00"` | SHA256 |
| `Sha512SaltedHashProvider` | `HashTypeCode` | `"01"` | SHA512 |

Type codes are ambiguous across contexts — `"00"` means AES for symmetric encryption, RSA for
asymmetric encryption, ECDSA-SHA256 for asymmetric signatures, HMAC-SHA256 for symmetric
signatures, and SHA256 for hashing.

### Stored Data Format

Type codes are embedded in stored output:
- Encryption: `{TypeCode}:{KeyVersion}:{Base64(ciphertext)}`
- Signatures: `{TypeCode}:{Base64(signature)}`
- Hashes: `{TypeCode}:{Base64(salt + hash)}`

After this change, stored data becomes self-documenting:
- `AES-256-CBC-PKCS7:1:Base64...` instead of `00:1:Base64...`
- `SHA256-Salted:Base64...` instead of `00:Base64...`

No data migration is needed — there is no production data depending on the current format.

## Proposed Change

### 1. Replace Type Codes with `ProviderName`

Rename and replace the existing abstract type code properties:
- `EncryptionTypeCode` → `ProviderName` (on encryption base classes and interfaces)
- `SignatureTypeCode` → `ProviderName` (on signature base classes and interfaces)
- `HashTypeCode` → `ProviderName` (on hash base class and interface)

`ProviderName` serves double duty: factory lookup key + human-readable display name. This
eliminates the need for a separate display property — one identifier instead of two.

### 2. Add `ProviderDescription`

Add a new `virtual` property with a plain English description of the provider's setup, covering
interoperability-critical details (IV handling, key format, output encoding, signature format).

Default implementation returns `GetType().Name`, so providers that don't override still emit
something useful.

### Why not structured data (JSON / Dictionary) for description?

Algorithm parameters are **not uniform** across providers, even within the same category:
- AES needs Mode + Padding; a future ChaCha20 wouldn't have those concepts
- RSA encryption uses OAEP padding; a hypothetical ECIES would need Curve + KDF instead
- ECDSA needs Curve; RSA signatures need Padding scheme

Plain English lets each provider describe itself in its own terms.

## Changes by Layer

### Base Classes

| Base Class | Remove | Add |
|------------|--------|-----|
| `SymmetricEncryptionProviderBase` | `abstract EncryptionTypeCode` | `abstract ProviderName`, `virtual ProviderDescription` |
| `AsymmetricEncryptionProviderBase` | `abstract EncryptionTypeCode` | `abstract ProviderName`, `virtual ProviderDescription` |
| `AsymmetricSignatureProviderBase` | `abstract SignatureTypeCode` | `abstract ProviderName`, `virtual ProviderDescription` |
| `SymmetricSignatureProviderBase` | `abstract SignatureTypeCode` | `abstract ProviderName`, `virtual ProviderDescription` |
| `SaltedHashProviderBase` | `abstract HashTypeCode` | `abstract ProviderName`, `virtual ProviderDescription` |

`ProviderName` stays `abstract` (replacing an existing abstract property). `ProviderDescription`
is `virtual` with a default:

```csharp
public virtual string ProviderDescription => GetType().Name;
```

### Interfaces

| Interface | Remove | Add |
|-----------|--------|-----|
| `ISymmetricEncryptionProvider` | `EncryptionTypeCode` | `ProviderName`, `ProviderDescription` |
| `IAsymmetricEncryptionProvider` | `EncryptionTypeCode` | `ProviderName`, `ProviderDescription` |
| `IAsymmetricSignatureProvider` | `SignatureTypeCode` | `ProviderName`, `ProviderDescription` |
| `ISymmetricSignatureProvider` | `SignatureTypeCode` | `ProviderName`, `ProviderDescription` |
| `IHashProvider` | `HashTypeCode` | `ProviderName`, `ProviderDescription` |

### Constants Classes

Remove the opaque code constants (or repurpose them with meaningful values):

| Class | Remove |
|-------|--------|
| `SymmetricEncryptionConstants` | `AES_CODE = "00"` |
| `AsymmetricEncryptionConstants` | `RSA_CODE = "00"` |
| `AsymmetricSignatureConstants` | `ECDSA_SHA256_CODE = "00"`, `RSA_SHA256_CODE = "01"` |
| `SymmetricSignatureConstants` | `HMAC_SHA256_CODE = "00"` |
| `HashConstants` | `SALTED_SHA256_CODE = "00"`, `SALTED_SHA512_CODE = "01"` |

Replace with constants using the `ProviderName` values if needed for factory registration.

### Factories

Update factory dictionaries to use `ProviderName` as the lookup key instead of type codes:

| Factory | Old Key | New Key |
|---------|---------|---------|
| `SymmetricEncryptionProviderFactory` | `"00"` | `"AES-256-CBC-PKCS7"` |
| `AsymmetricEncryptionProviderFactory` | `"00"` | `"RSA-2048-OAEP-SHA256"` |
| `AsymmetricSignatureProviderFactory` | `"00"`, `"01"` | `"ECDSA-P256-SHA256"`, `"RSA-2048-PKCS1-SHA256"` |
| `SymmetricSignatureProviderFactory` | `"00"` | `"HMAC-SHA256"` |
| `HashProviderFactory` | `"00"`, `"01"` | `"SHA256-Salted"`, `"SHA512-Salted"` |

### Concrete Implementations — ProviderName Values

`ProviderName` encodes all settings critical for cross-platform interoperability.

| Provider | `ProviderName` Value | Why |
|----------|---------------------|-----|
| `AesEncryptionProvider` | `"AES-256-CBC-PKCS7"` | Key size + cipher mode + padding are all required to decrypt |
| `RsaEncryptionProvider` | `"RSA-2048-OAEP-SHA256"` | Key size + padding scheme + OAEP hash are all required to decrypt |
| `ECDsaSignatureProvider` | `"ECDSA-P256-SHA256"` | Curve + hash algorithm are required to verify |
| `RsaSignatureProvider` | `"RSA-2048-PKCS1-SHA256"` | Key size + signature padding + hash are required to verify |
| `HmacSha256SignatureProvider` | `"HMAC-SHA256"` | Hash algorithm is sufficient |
| `Sha256SaltedHashProvider` | `"SHA256-Salted"` | Algorithm + salting strategy |
| `Sha512SaltedHashProvider` | `"SHA512-Salted"` | Algorithm + salting strategy |

Where settings are configurable (RSA key size, ECDSA curve, hash algorithm), `ProviderName`
should reflect the **actual configured values**, built dynamically in the property getter.

### Concrete Implementations — ProviderDescription Values

`ProviderDescription` conveys interoperability-critical details in plain English.

| Provider | `ProviderDescription` Value |
|----------|-----------------------------|
| `AesEncryptionProvider` | `"AES encryption using CBC mode with PKCS7 padding. A 16-byte IV is randomly generated per operation and prepended to the ciphertext. Output format: Base64([16-byte IV \| ciphertext]). Keys are Base64-encoded."` |
| `RsaEncryptionProvider` | `"RSA encryption with OAEP-SHA256 padding. Keys use PKCS#8 (private) and SubjectPublicKeyInfo (public) format, Base64-encoded. Output is Base64-encoded."` |
| `ECDsaSignatureProvider` | `"ECDSA digital signature using the P-256 curve. Signatures are in DER format, Base64-encoded. Keys use PKCS#8 (private) and SubjectPublicKeyInfo (public) format, Base64-encoded."` |
| `RsaSignatureProvider` | `"RSA digital signature with PKCS#1 v1.5 padding. Keys use PKCS#8 (private) and SubjectPublicKeyInfo (public) format, Base64-encoded. Signature is Base64-encoded."` |
| `HmacSha256SignatureProvider` | `"HMAC-SHA256 message authentication. Key is Base64-encoded. Signature output is Base64-encoded."` |
| `Sha256SaltedHashProvider` | `"SHA256 salted hash. A 16-byte random salt is generated per operation and prepended to the input before hashing. Output format: {ProviderName}:{Base64(salt + hash)}. Salt is embedded in the output for verification."` |
| `Sha512SaltedHashProvider` | `"SHA512 salted hash. A 16-byte random salt is generated per operation and prepended to the input before hashing. Output format: {ProviderName}:{Base64(salt + hash)}. Salt is embedded in the output for verification."` |

Where settings are configurable, `ProviderDescription` should reflect actual configured values.

### Downstream Consumer (Corely.IAM)

Once `ProviderName` replaces the type codes on Corely.Security providers, Corely.IAM's
`IIam*Provider` wrappers can:
- Replace `ProviderTypeCode` with `ProviderName` — direct passthrough from the underlying provider
- Expose `ProviderDescription` as a new property
- The account detail web UI shows "AES-256-CBC-PKCS7" with a description tooltip instead of "00"

## Tests

### Existing Tests to Update

~30 test files reference `EncryptionTypeCode`, `SignatureTypeCode`, or `HashTypeCode`. All must
be renamed to `ProviderName` and their expected values updated from `"00"`/`"01"` to the new
provider name strings.

**Base class tests** (mock implementations + validation tests):
- `SymmetricEncryptionProviderBaseTests.cs` — mock overrides + null/empty/colon validation tests
- `AsymmetricEncryptionProviderBaseTests.cs` — same
- `AsymmetricSignatureProviderBaseTests.cs` — same
- `SymmetricSignatureProviderBaseTests.cs` — same
- `SaltedHashProviderBaseTests.cs` — same

**Generic provider tests** (format assertions on encrypted/hashed output):
- `SymmetricEncryptionProviderGenericTests.cs` — `StartsWith(EncryptionTypeCode)` assertions
- `AsymmetricEncryptionProviderGenericTests.cs` — same
- `SaltedHashProviderGenericTests.cs` — `StartsWith(HashTypeCode)` assertions

**Concrete provider tests** (type code value assertions):
- `AesEncryptionProviderTests.cs` — `Assert.Equal(AES_CODE, ...EncryptionTypeCode)`
- `RsaEncryptionProviderTests.cs` — `Assert.Equal(RSA_CODE, ...EncryptionTypeCode)`
- `ECDsaSignatureProviderTests.cs` — `Assert.Equal(ECDSA_SHA256_CODE, ...SignatureTypeCode)`
- `RsaSignatureProviderTests.cs` — `Assert.Equal(RSA_SHA256_CODE, ...SignatureTypeCode)`
- `HmacSha256SignatureProviderTests.cs` — `Assert.Equal(HMAC_SHA256_CODE, ...SignatureTypeCode)`
- `Sha256SaltedHashProviderTests.cs` — `Assert.Equal(SALTED_SHA256_CODE, ...HashTypeCode)`
- `Sha512SaltedHashProviderTests.cs` — `Assert.Equal(SALTED_SHA512_CODE, ...HashTypeCode)`

**Factory tests** (provider code lookups + default provider assertions):
- `SymmetricEncryptionProviderFactoryTests.cs`
- `AsymmetricEncryptionProviderFactoryTests.cs`
- `SymmetricSignatureProviderFactoryTests.cs` (file may be named `SymmetricEncryptionProviderFactoryTests.cs` in Signature folder)
- `AsymmetricSignatureProviderFactoryTests.cs`
- `HashProviderFactoryTests.cs`

### New Tests to Add

1. `ProviderName` returns the expected value for each concrete provider
2. `ProviderDescription` returns a non-empty, meaningful string (not `GetType().Name`)
3. For configurable providers, verify name/description reflect actual configured values
4. Default base class behavior: a provider that does **not** override `ProviderDescription`
   should return `GetType().Name`

## DemoApp Updates

`Corely.Security.DemoApp/Program.cs` has ~20 references to type code constants for factory
initialization and console output. All must be updated:
- Factory constructors: `new ...Factory(SymmetricEncryptionConstants.AES_CODE)` → new constant name
- Console output: `provider.EncryptionTypeCode` → `provider.ProviderName`
- Custom provider registration: `factory.AddProvider(provider.EncryptionTypeCode, ...)` → `factory.AddProvider(provider.ProviderName, ...)`

## Documentation Updates

9 docs files reference type code constants and need updating:
- `Docs/key-providers.md` — `SymmetricEncryptionConstants.AES_CODE`, `AsymmetricSignatureConstants.ECDSA_SHA256_CODE`
- `Docs/symmetric-signatures.md` — `SymmetricSignatureConstants.HMAC_SHA256_CODE`
- `Docs/symmetric-encryption.md` — `SymmetricEncryptionConstants.AES_CODE`
- `Docs/asymmetric-signatures.md` — `AsymmetricSignatureConstants.ECDSA_SHA256_CODE`
- `Docs/asymmetric-encryption.md` — `AsymmetricEncryptionConstants.RSA_CODE`
- `Docs/hashing.md` — `HashConstants.SALTED_SHA256_CODE`
- `Docs/index.md` — `HashConstants.SALTED_SHA256_CODE`
- `Docs/dependency-injection.md` — all constants
- `Docs/provider-factories.md` — `SymmetricEncryptionConstants.AES_CODE`

## NuGet Version Bump

| File | Property | From | To |
|------|----------|------|----|
| `Corely.Security/Corely.Security.csproj` | `<Version>` | `1.0.1` | `1.0.2` |
