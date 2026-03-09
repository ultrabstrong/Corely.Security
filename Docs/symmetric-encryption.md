# Symmetric Encryption

AES provider included (provider name `"AES-256-CBC-PKCS7"`). Output embeds provider name and key version for rotation support.

Encrypt / decrypt:
```csharp
var factory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
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

Add custom provider (passthrough example in demo):
```csharp
factory.AddProvider("DemoSymEnc", new DemoSymmetricEncryptionProvider());
```
Relevant demos: RunSymmetricEncryptionDemo, RunAddCustomProvidersDemo, SymmetricKeyStoreDemo.