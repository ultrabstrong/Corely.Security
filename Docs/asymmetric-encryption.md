# Asymmetric Encryption

RSA provider included (provider name `"RSA-OAEP-SHA256"`). Uses key versioning like symmetric
encryption.

The legacy name `"RSA-2048-OAEP-SHA256"` stays registered as a read alias, so values written under
it still decrypt. Key size comes from whichever key the key store supplies, not from provider
configuration, so it is not claimed in the name.

Usage:
```csharp
var factory = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);
var provider = factory.GetDefaultProvider();
var keyProv = provider.GetAsymmetricKeyProvider();
var (pub, priv) = keyProv.CreateKeys();
var keyStore = new InMemoryAsymmetricKeyStoreProvider(pub, priv);
var cipher = provider.Encrypt("secret", keyStore);
var plain = provider.Decrypt(cipher, keyStore);
```
Rotate & re-encrypt:
```csharp
var (newPub, newPriv) = keyProv.CreateKeys();
keyStore.Add(newPub, newPriv);
var rotatedCipher = provider.ReEncrypt(cipher, keyStore);
```
Format: `providerName:keyVersion:base64Cipher`. Note: cipher size depends on key size; rotating keys does not invalidate previously encrypted values�they can still be decrypted using stored versioned keys.

Custom provider example (demo) uses a passthrough provider name `"DemoAsymEnc"`.

See demos: RunAsymmetricEncryptionDemo, AsymmetricKeyStoreDemo, RunAddCustomProvidersDemo.