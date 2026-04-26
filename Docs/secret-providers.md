# Secret Providers

Generate opaque application secrets for workflows like password recovery, one-time tokens, selector/verifier pairs, and other cases where a value must be random but is not an encryption or signing key.

## Included Provider

- `RandomSecretProvider` - generates URL-safe random secrets using cryptographically secure randomness

## Example

```csharp
var secretProvider = new RandomSecretProvider();
var secret = secretProvider.CreateSecret();
var isValid = secretProvider.IsSecretValid(secret);
```

## Behavior

- Secrets are generated from cryptographically random bytes
- Output is Base64Url-encoded, so it is safe to embed in URLs and tokens
- Validation checks that the secret decodes successfully and matches the expected byte length

## When to use this instead of a key provider

Use a secret provider when you need an opaque random value that will be transported or compared by the application.

Use a key provider when you need cryptographic key material for encryption or signing algorithms.
