# Corely.Security Documentation

## Overview
Corely.Security gives you small plug-in style building blocks for application "lock and key" needs. You ask a factory for a provider (hashing, encryption, signatures). That provider uses a key (from a key provider) fetched through a versioned key store so you can rotate keys later. The provider returns a self-describing string (it starts with a human-readable provider name, sometimes also a key version) so the library can figure out how to verify or decrypt it later without you tracking metadata. You can plug in custom providers or real key management backends, and everything wires cleanly through dependency injection.

### Concept Map
```mermaid
graph TD
    A[Application Code] --> B[Factories]
    B --> C[Hash Providers]
    B --> D[Symmetric Encryption Providers]
    B --> E[Asymmetric Encryption Providers]
    B --> F[Symmetric Signature Providers]
    B --> G[Asymmetric Signature Providers]

    C --> H[Key Providers]
    D --> H
    E --> H
    F --> H
    G --> H

    H --> I[Generated Keys]
    I --> J["Key Stores (Versioned)"]
    J --> D
    J --> E
    J --> F
    J --> G
    C --> J

    D --> K["Encrypted Values (providerName:keyVersion:cipher)"]
    E --> K
    F --> L["Signatures (bare signature, no prefix)"]
    G --> L
    C --> M["Hashes (providerName:base64SaltPlusHash)"]

    N[DI Container] --> B
    N --> O[Password Validation Provider]

    style K fill:#1e3a8a,stroke:#0f172a,color:#ffffff
    style L fill:#1e3a8a,stroke:#0f172a,color:#ffffff
    style M fill:#1e3a8a,stroke:#0f172a,color:#ffffff
    style J fill:#065f46,stroke:#064e3b,color:#ffffff
    style H fill:#065f46,stroke:#064e3b,color:#ffffff
    style B fill:#92400e,stroke:#78350f,color:#ffffff
```

These blocks provide small, composable building blocks for application-level cryptography & credential workflows:
- Uniform provider interfaces for hashing, encryption, and digital signatures
- URL-safe secret generation for token and verifier workflows
- Pluggable factories keyed by human-readable provider names (enables encoded self-describing values)
- Versioned key stores to support seamless key rotation + on-demand re-encryption
- Minimal DI-friendly construction (no static globals)
- Clear value formats so decryption / verification can auto-select the correct provider

Each topic below maps to a runnable demo in `Corely.Security.DemoApp/Program.cs`.

## Topics
- [Hashing](hashing.md)
- [Symmetric Encryption](symmetric-encryption.md)
- [Asymmetric Encryption](asymmetric-encryption.md)
- [Symmetric Signatures](symmetric-signatures.md)
- [Asymmetric Signatures](asymmetric-signatures.md)
- [Key Providers](key-providers.md)
- [Secret Providers](secret-providers.md)
- [Key Stores](key-stores.md)
- [Provider Factories & Custom Providers](provider-factories.md)
- [Dependency Injection](dependency-injection.md)
- [Password Validation](password-validation.md)

## Value Encoding Formats
Hashes and encrypted values are prefixed with a human-readable provider name (and, for
encryption, a key version) so factories can auto-resolve providers. Signatures are not: they are
verified against a provider and key store the caller already chose.

| Feature | Format |
|---------|--------|
| Hash | `providerName:base64SaltPlusHash` |
| Symmetric Encryption | `providerName:keyVersion:cipherBase64` |
| Asymmetric Encryption | `providerName:keyVersion:cipherBase64` |
| Symmetric Signature | `signatureBase64` (no prefix) |
| Asymmetric Signature | `signatureBase64` (no prefix) |

## Quick Start
```csharp
var hashFactory = new HashProviderFactory(HashConstants.SALTED_SHA256_CODE);
var hash = hashFactory.GetDefaultProvider().Hash("secret");
var valid = hashFactory.GetProviderToVerify(hash).Verify("secret", hash);
```
See individual topic files for more examples. All end-to-end flows are shown in the DemoApp.
