# Symmetric Encryption

Two AES providers included. Output embeds provider name and key version for rotation support.

Default providers:
- AES-256-GCM (`"AES-256-GCM"`) — authenticated, detects tampering on decrypt
- AES-256-CBC-PKCS7 (`"AES-256-CBC-PKCS7"`) — no authentication

Encrypt / decrypt:
```csharp
var factory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_GCM_CODE);
var provider = factory.GetDefaultProvider();
var keyStore = new InMemorySymmetricKeyStoreProvider(provider.GetSymmetricKeyProvider().CreateKey());
var cipher = provider.Encrypt("secret", keyStore);
var plain = provider.Decrypt(cipher, keyStore);
```
Rotate & re-encrypt:
```csharp
keyStore.Add(provider.GetSymmetricKeyProvider().CreateKey());
var rotatedCipher = provider.ReEncrypt(cipher, keyStore);
```
Format: `providerName:keyVersion:base64Cipher`. Note: AES key size is determined by the generated key (Base64 length reflects raw key bytes) and the version enables rotation.

GCM prepends a 12-byte nonce and the 16-byte authentication tag to the ciphertext, so its payload is `base64([nonce | tag | cipher])`. Decrypting a modified value throws rather than returning wrong plaintext. CBC prepends a 16-byte IV and cannot detect modification — prefer GCM unless you are reading values an older version wrote.

Add custom provider (passthrough example in demo):
```csharp
factory.AddProvider("DemoSymEnc", new DemoSymmetricEncryptionProvider());
```
Relevant demos: RunSymmetricEncryptionDemo, RunAddCustomProvidersDemo, SymmetricKeyStoreDemo.
