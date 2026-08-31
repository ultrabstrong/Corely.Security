using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.Encryption.Providers;
using Corely.Security.Hashing;
using Corely.Security.Hashing.Factories;
using Corely.Security.Hashing.Providers;
using Corely.Security.Keys;
using Corely.Security.KeyStore;
using Corely.Security.PasswordValidation.Models;
using Corely.Security.PasswordValidation.Providers;
using Corely.Security.Secrets;
using Corely.Security.Signature;
using Corely.Security.Signature.Factories;
using Corely.Security.Signature.Providers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Corely.Security.DemoApp;

internal class Program
{
    static void Main()
    {
        Console.WriteLine("=== Corely.Security Demo ===");

        // Demonstrate key providers
        RunKeyProvidersDemo();
        RunSecretProvidersDemo();

        // Demonstrate simple encryption, hashing, and signing operations
        RunHashingDemo();
        RunSymmetricEncryptionDemo();
        RunSymmetricSignatureDemo();
        RunAsymmetricEncryptionDemo();
        RunAsymmetricSignatureDemo();

        // Demonstrate adding custom providers for encryption, hashing, and signing
        RunAddCustomProvidersDemo();

        // Demonstrate dependency injection registration and resolution
        RunDependencyInjectionDemo();

        // Demonstrate direct usage of key store providers (symmetric & asymmetric)
        RunKeyStoreProvidersDemo();

        // Demonstrate password validation logic
        RunPasswordValidationDemo();
    }

    private static void RunKeyProvidersDemo()
    {
        Console.WriteLine("\n-- Key Providers Demo --");

        void SymmetricAesKeyProviderDemo()
        {
            var factory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
            var provider = factory.GetDefaultProvider();
            var keyProvider = provider.GetSymmetricKeyProvider();
            var key = keyProvider.CreateKey();
            Console.WriteLine($"  AES   Key Length: {key.Length} bytes | Valid: {keyProvider.IsKeyValid(key)}");
        }

        void SymmetricHmacKeyProviderDemo()
        {
            var factory = new SymmetricSignatureProviderFactory(SymmetricSignatureConstants.HMAC_SHA256_CODE);
            var provider = factory.GetDefaultProvider();
            var keyProvider = provider.GetSymmetricKeyProvider();
            var key = keyProvider.CreateKey();
            Console.WriteLine($"  HMAC  Key Length: {key.Length} bytes | Valid: {keyProvider.IsKeyValid(key)}");
        }

        void AsymmetricRsaKeyProviderDemo()
        {
            // Use RSA encryption provider to access RSA key provider
            var factory = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);
            var provider = factory.GetDefaultProvider();
            var keyProvider = provider.GetAsymmetricKeyProvider();
            var (pub, priv) = keyProvider.CreateKeys();
            Console.WriteLine($"  RSA   PublicKeyBytes: {pub.Length} | PrivateKeyBytes: {priv.Length} | Valid: {keyProvider.IsKeyValid(pub, priv)}");
        }

        void AsymmetricEcdsaKeyProviderDemo()
        {
            // Use ECDSA signature provider to access ECDSA key provider
            var factory = new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE);
            var provider = factory.GetDefaultProvider();
            var keyProvider = provider.GetAsymmetricKeyProvider();
            var (pub, priv) = keyProvider.CreateKeys();
            Console.WriteLine($"  ECDSA PublicKeyBytes: {pub.Length} | PrivateKeyBytes: {priv.Length} | Valid: {keyProvider.IsKeyValid(pub, priv)}");
        }

        // Execute key provider demos
        SymmetricAesKeyProviderDemo();
        SymmetricHmacKeyProviderDemo();
        AsymmetricRsaKeyProviderDemo();
        AsymmetricEcdsaKeyProviderDemo();
    }

    private static void RunSecretProvidersDemo()
    {
        Console.WriteLine("\n-- Secret Providers Demo --");

        var secretProvider = new RandomSecretProvider();
        var secret = secretProvider.CreateSecret();

        Console.WriteLine($"Secret: {secret}");
        Console.WriteLine($"Valid: {secretProvider.IsSecretValid(secret)}");
    }

    private static void RunHashingDemo()
    {
        Console.WriteLine("\n-- Hashing --");
        var hashFactory = new HashProviderFactory(HashConstants.SALTED_SHA256_CODE);
        var hashProvider = hashFactory.GetDefaultProvider();

        var value = "SuperSecretPassword!";
        var hash = hashProvider.Hash(value);
        var verified = hashProvider.Verify(value, hash);
        var failedVerify = hashProvider.Verify(value + "X", hash);

        Console.WriteLine($"Provider Name: {hashProvider.ProviderName}");
        Console.WriteLine($"Provider Description: {hashProvider.ProviderDescription}");
        Console.WriteLine($"Original: {value}");
        Console.WriteLine($"Hash: {hash}");
        Console.WriteLine($"Verify (correct): {verified}");
        Console.WriteLine($"Verify (incorrect): {failedVerify}");
    }

    private static void RunSymmetricEncryptionDemo()
    {
        Console.WriteLine("\n-- Symmetric Encryption (AES) --");
        var encryptionFactory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
        var provider = encryptionFactory.GetDefaultProvider();

        var keyProvider = provider.GetSymmetricKeyProvider();
        var keyStore = new InMemorySymmetricKeyStoreProvider(keyProvider.CreateKey()); // version 1

        var plaintext = "Sensitive data that must be encrypted.";
        var encrypted = provider.Encrypt(plaintext, keyStore);
        var decrypted = provider.Decrypt(encrypted, keyStore);

        Console.WriteLine($"Provider Name: {provider.ProviderName}");
        Console.WriteLine($"Provider Description: {provider.ProviderDescription}");
        Console.WriteLine($"Plaintext: {plaintext}");
        Console.WriteLine($"Encrypted: {encrypted}");
        Console.WriteLine($"Decrypted: {decrypted}");

        // Rotate key (version 2) and re-encrypt
        keyStore.Add(keyProvider.CreateKey());
        var reEncrypted = provider.ReEncrypt(encrypted, keyStore);
        var reDecrypted = provider.Decrypt(reEncrypted, keyStore);
        Console.WriteLine($"Re-Encrypted (rotated to version {keyStore.GetCurrentVersion()}): {reEncrypted}");
        Console.WriteLine($"Re-Decrypted: {reDecrypted}");
    }

    private static void RunSymmetricSignatureDemo()
    {
        Console.WriteLine("\n-- Symmetric Signature (HMAC SHA256) --");
        var signatureFactory = new SymmetricSignatureProviderFactory(SymmetricSignatureConstants.HMAC_SHA256_CODE);
        var provider = signatureFactory.GetDefaultProvider();

        var keyProvider = provider.GetSymmetricKeyProvider();
        var keyStore = new InMemorySymmetricKeyStoreProvider(keyProvider.CreateKey()); // version 1

        var data = "Payload to authenticate";
        var signature = provider.Sign(data, keyStore);
        var verified = provider.Verify(data, signature, keyStore);
        var failed = provider.Verify(data + "tampered", signature, keyStore);

        Console.WriteLine($"Provider Name: {provider.ProviderName}");
        Console.WriteLine($"Provider Description: {provider.ProviderDescription}");
        Console.WriteLine($"Data: {data}");
        Console.WriteLine($"Signature (Base64): {signature}");
        Console.WriteLine($"Verify (correct): {verified}");
        Console.WriteLine($"Verify (tampered): {failed}");

        // Demonstrate rotation impact
        keyStore.Add(keyProvider.CreateKey()); // version 2 (existing signature still validated with current key only)
        var signatureV2 = provider.Sign(data, keyStore); // new signature with new key
        var verifiedV2 = provider.Verify(data, signatureV2, keyStore);
        Console.WriteLine($"Signature after rotation (version {keyStore.GetCurrentVersion()}): {signatureV2}");
        Console.WriteLine($"Verify (rotated key): {verifiedV2}");
    }

    private static void RunAsymmetricEncryptionDemo()
    {
        Console.WriteLine("\n-- Asymmetric Encryption (RSA) --");
        var encryptionFactory = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);
        var provider = encryptionFactory.GetDefaultProvider();

        var keyProvider = provider.GetAsymmetricKeyProvider();
        var (pub1, priv1) = keyProvider.CreateKeys();
        var keyStore = new InMemoryAsymmetricKeyStoreProvider(pub1, priv1); // version 1

        var plaintext = "Highly sensitive asymmetric data";
        var encrypted = provider.Encrypt(plaintext, keyStore);
        var decrypted = provider.Decrypt(encrypted, keyStore);
        Console.WriteLine($"Provider Name: {provider.ProviderName}");
        Console.WriteLine($"Provider Description: {provider.ProviderDescription}");
        Console.WriteLine($"Plaintext: {plaintext}");
        Console.WriteLine($"Encrypted: {encrypted}");
        Console.WriteLine($"Decrypted: {decrypted}");

        // Rotate keys (version 2) and re-encrypt
        var (pub2, priv2) = keyProvider.CreateKeys();
        keyStore.Add(pub2, priv2);
        var reEncrypted = provider.ReEncrypt(encrypted, keyStore);
        var reDecrypted = provider.Decrypt(reEncrypted, keyStore);
        Console.WriteLine($"Re-Encrypted (rotated to version {keyStore.GetCurrentVersion()}): {reEncrypted}");
        Console.WriteLine($"Re-Decrypted: {reDecrypted}");
    }

    private static void RunAsymmetricSignatureDemo()
    {
        Console.WriteLine("\n-- Asymmetric Signature (ECDSA / RSA) --");
        var signatureFactory = new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE);
        var ecdsaProvider = signatureFactory.GetDefaultProvider();
        var rsaProvider = signatureFactory.GetProvider(AsymmetricSignatureConstants.RSA_SHA256_CODE);

        var ecdsaKeyProvider = ecdsaProvider.GetAsymmetricKeyProvider();
        var (ecdsaPub, ecdsaPriv) = ecdsaKeyProvider.CreateKeys();
        var ecdsaKeyStore = new InMemoryAsymmetricKeyStoreProvider(ecdsaPub, ecdsaPriv);

        var data = "Document requiring digital signature";
        var ecdsaSignature = ecdsaProvider.Sign(data, ecdsaKeyStore);
        var ecdsaVerified = ecdsaProvider.Verify(data, ecdsaSignature, ecdsaKeyStore);
        Console.WriteLine($"ECDSA Signature: {ecdsaSignature[..Math.Min(60, ecdsaSignature.Length)]}...");
        Console.WriteLine($"ECDSA Verified: {ecdsaVerified}");

        var rsaKeyProvider = rsaProvider.GetAsymmetricKeyProvider();
        var (rsaPub, rsaPriv) = rsaKeyProvider.CreateKeys();
        var rsaKeyStore = new InMemoryAsymmetricKeyStoreProvider(rsaPub, rsaPriv);
        var rsaSignature = rsaProvider.Sign(data, rsaKeyStore);
        var rsaVerified = rsaProvider.Verify(data, rsaSignature, rsaKeyStore);
        Console.WriteLine($"RSA Signature: {rsaSignature[..Math.Min(60, rsaSignature.Length)]}...");
        Console.WriteLine($"RSA Verified: {rsaVerified}");
    }

    private static void RunAddCustomProvidersDemo()
    {
        Console.WriteLine("\n-- Adding Custom Providers --");

        void HashProviderDemo()
        {
            var factory = new HashProviderFactory(HashConstants.SALTED_SHA256_CODE);
            var provider = new DemoHashProvider();
            factory.AddProvider(provider.ProviderName, provider);
            var hash = provider.Hash("anything");
            Console.WriteLine($"Custom Hash Provider => {hash}");
        }

        void SymmetricEncryptionProviderDemo()
        {
            var factory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
            var provider = new DemoSymmetricEncryptionProvider();
            factory.AddProvider(provider.ProviderName, provider);
            var keyStore = new InMemorySymmetricKeyStoreProvider(new byte[16]);
            var encrypted = provider.Encrypt("demo", keyStore);
            Console.WriteLine($"Custom Symmetric Encryption => {encrypted}");
        }

        void AsymmetricEncryptionProviderDemo()
        {
            var factory = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);
            var provider = new DemoAsymmetricEncryptionProvider();
            factory.AddProvider(provider.ProviderName, provider);
            var keyStore = new InMemoryAsymmetricKeyStoreProvider(new byte[8], new byte[8]);
            var encrypted = provider.Encrypt("demo", keyStore);
            Console.WriteLine($"Custom Asymmetric Encryption => {encrypted}");
        }

        void SymmetricSignatureProviderDemo()
        {
            var factory = new SymmetricSignatureProviderFactory(SymmetricSignatureConstants.HMAC_SHA256_CODE);
            var provider = new DemoSymmetricSignatureProvider("SIG");
            factory.AddProvider(provider.ProviderName, provider);
            var keyStore = new InMemorySymmetricKeyStoreProvider(new byte[16]);
            var signature = provider.Sign("data", keyStore);
            Console.WriteLine($"Custom Symmetric Signature => {signature}");
        }

        void AsymmetricSignatureProviderDemo()
        {
            var factory = new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE);
            var provider = new DemoAsymmetricSignatureProvider("ASIG");
            factory.AddProvider(provider.ProviderName, provider);
            var keyStore = new InMemoryAsymmetricKeyStoreProvider(new byte[8], new byte[8]);
            var signature = provider.Sign("data", keyStore);
            Console.WriteLine($"Custom Asymmetric Signature => {signature}");
        }

        // Execute local demos
        HashProviderDemo();
        SymmetricEncryptionProviderDemo();
        AsymmetricEncryptionProviderDemo();
        SymmetricSignatureProviderDemo();
        AsymmetricSignatureProviderDemo();
    }

    private static void RunDependencyInjectionDemo()
    {
        Console.WriteLine("\n-- Dependency Injection Registration Demo --");

        var services = new ServiceCollection();

        services.AddSingleton<ISymmetricEncryptionProviderFactory>(_ =>
            new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE));
        services.AddSingleton<IAsymmetricEncryptionProviderFactory>(_ =>
            new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE));
        services.AddSingleton<IAsymmetricSignatureProviderFactory>(_ =>
            new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE));
        services.AddSingleton<IHashProviderFactory>(_ =>
            new HashProviderFactory(HashConstants.SALTED_SHA256_CODE));

        services.AddScoped<IPasswordValidationProvider, PasswordValidationProvider>();
        services.AddSingleton<ISecretProvider, RandomSecretProvider>();

        // Manually register options since no IConfiguration binding here
        services.AddSingleton(
            _ => Options.Create(new PasswordValidationOptions
            {
                MinimumLength = 8,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireDigit = true,
                RequireNonAlphanumeric = false
            }));

        using ServiceProvider provider = services.BuildServiceProvider();

        var hashFactory = provider.GetRequiredService<IHashProviderFactory>();
        var hashProvider = hashFactory.GetDefaultProvider();
        var sampleHash = hashProvider.Hash("demo");
        Console.WriteLine($"Resolved Hash Provider Hash => {sampleHash}");

        var pwdValidator = provider.GetRequiredService<IPasswordValidationProvider>();
        var pwdResult = pwdValidator.ValidatePassword("Abcdef1");
        Console.WriteLine($"Password Validation Success => {pwdResult.IsSuccess}");

        var secretProvider = provider.GetRequiredService<ISecretProvider>();
        var secret = secretProvider.CreateSecret();
        Console.WriteLine($"Generated Secret Valid => {secretProvider.IsSecretValid(secret)}");
    }

    private static void RunKeyStoreProvidersDemo()
    {
        Console.WriteLine("\n-- Key Store Providers Demo --");

        void SymmetricKeyStoreDemo()
        {
            Console.WriteLine("\n  * Symmetric Key Store *");
            var symFactory = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE);
            var symProvider = symFactory.GetDefaultProvider();
            var symKeyCreator = symProvider.GetSymmetricKeyProvider();

            // Seed key store with initial key (version 1)
            var initialSymKey = symKeyCreator.CreateKey();
            var symKeyStore = new InMemorySymmetricKeyStoreProvider(initialSymKey);
            Console.WriteLine($"Initial Symmetric Key Version: {symKeyStore.GetCurrentVersion()}");

            var secret = "RotateMeSymmetric";
            var encryptedV1 = symProvider.Encrypt(secret, symKeyStore);
            Console.WriteLine($"Encrypted (v1): {encryptedV1}");

            // Rotate to version 2
            symKeyStore.Add(symKeyCreator.CreateKey());
            Console.WriteLine($"Rotated Symmetric Key Version: {symKeyStore.GetCurrentVersion()}");

            // Re-encrypt existing ciphertext to current version (demonstrates automated decrypt & re-encrypt flow)
            var reEncryptedToV2 = symProvider.ReEncrypt(encryptedV1, symKeyStore);
            Console.WriteLine($"Re-Encrypted (v2): {reEncryptedToV2}");
            var decryptedAfterRotation = symProvider.Decrypt(reEncryptedToV2, symKeyStore);
            Console.WriteLine($"Decrypted (v2): {decryptedAfterRotation}");
        }

        void AsymmetricKeyStoreDemo()
        {
            Console.WriteLine("\n  * Asymmetric Key Store *");
            var asymFactory = new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE);
            var asymProvider = asymFactory.GetDefaultProvider();
            var asymKeyCreator = asymProvider.GetAsymmetricKeyProvider();

            // Seed asymmetric key store (version 1)
            var (pub1, priv1) = asymKeyCreator.CreateKeys();
            var asymKeyStore = new InMemoryAsymmetricKeyStoreProvider(pub1, priv1);
            Console.WriteLine($"Initial Asymmetric Key Version: {asymKeyStore.GetCurrentVersion()}");

            var asymSecret = "RotateMeAsymmetric";
            var asymEncryptedV1 = asymProvider.Encrypt(asymSecret, asymKeyStore);
            Console.WriteLine($"Encrypted (v1): {asymEncryptedV1}");

            // Rotate asymmetric keys (version 2)
            var (pub2, priv2) = asymKeyCreator.CreateKeys();
            asymKeyStore.Add(pub2, priv2);
            Console.WriteLine($"Rotated Asymmetric Key Version: {asymKeyStore.GetCurrentVersion()}");

            var asymReEncryptedV2 = asymProvider.ReEncrypt(asymEncryptedV1, asymKeyStore);
            Console.WriteLine($"Re-Encrypted (v2): {asymReEncryptedV2}");
            var asymDecryptedV2 = asymProvider.Decrypt(asymReEncryptedV2, asymKeyStore);
            Console.WriteLine($"Decrypted (v2): {asymDecryptedV2}");
        }

        // Execute local key store demos
        SymmetricKeyStoreDemo();
        AsymmetricKeyStoreDemo();
    }

    private static void RunPasswordValidationDemo()
    {
        Console.WriteLine("\n-- Password Validation Demo --");

        // Configure validation rules (could mirror what DI would inject)
        var options = Options.Create(new PasswordValidationOptions
        {
            MinimumLength = 8,
            RequireUppercase = true,
            RequireLowercase = true,
            RequireDigit = true,
            RequireNonAlphanumeric = true
        });

        var validator = new PasswordValidationProvider(options);

        string[] samples =
        {
            "Passw0rd!",      // valid
            "password",       // no upper, digit, special
            "PASSWORD1",      // no lower, no special
            "Passw0rd",       // missing special
            "Pw0!",           // too short
            "ValidPass1#"      // valid
        };

        foreach (var pwd in samples)
        {
            var result = validator.ValidatePassword(pwd);
            if (result.IsSuccess)
            {
                Console.WriteLine($"  VALID   : '{pwd}'");
            }
            else
            {
                Console.WriteLine($"  INVALID : '{pwd}' -> [{string.Join(", ", result.ValidationFailures)}]");
            }
        }
    }
}

// --- Demo-only Custom Provider Implementations ---
internal sealed class DemoHashProvider : SaltedHashProviderBase
{
    // Unique demo provider name (not conflicting with built-in providers).
    public DemoHashProvider()
        : base("DemoHash") { }

    public override string ProviderDescription => "Demo hash provider for testing";

    protected override byte[] HashInternal(byte[] value)
     => SHA256.HashData(value);
}

internal sealed class DemoSymmetricEncryptionProvider : SymmetricEncryptionProviderBase
{
    // Unique demo provider name (built-in AES uses "AES-256-CBC-PKCS7").
    public DemoSymmetricEncryptionProvider()
        : base("DemoSymEnc") { }

    public override string ProviderDescription => "Demo symmetric encryption provider for testing";
    protected override string DecryptInternal(string value, ReadOnlySpan<byte> key) => value;
    protected override string EncryptInternal(string value, ReadOnlySpan<byte> key) => value;
    public override ISymmetricKeyProvider GetSymmetricKeyProvider() => new DemoSymmetricKeyProvider();
}

internal sealed class DemoAsymmetricEncryptionProvider : AsymmetricEncryptionProviderBase
{
    // Unique demo provider name (built-in RSA uses "RSA-2048-OAEP-SHA256").
    public DemoAsymmetricEncryptionProvider()
        : base("DemoAsymEnc") { }

    public override string ProviderDescription => "Demo asymmetric encryption provider for testing";
    protected override string DecryptInternal(string value, ReadOnlySpan<byte> privateKey) => value;
    protected override string EncryptInternal(string value, ReadOnlySpan<byte> publicKey) => value;
    public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => new DemoAsymmetricKeyProvider();
}

internal sealed class DemoSymmetricSignatureProvider : SymmetricSignatureProviderBase
{
    // Unique demo provider name (built-in HMAC SHA256 uses "HMAC-SHA256").
    public override string ProviderDescription => "Demo symmetric signature provider for testing";
    private readonly string _signatureValue;
    public DemoSymmetricSignatureProvider(string signatureValue)
        : base("DemoSymSig") => _signatureValue = signatureValue;
    protected override string SignInternal(string value, ReadOnlySpan<byte> key) => _signatureValue;
    protected override bool VerifyInternal(string value, string signature, ReadOnlySpan<byte> key) => signature == _signatureValue;
    public override ISymmetricKeyProvider GetSymmetricKeyProvider() => new DemoSymmetricKeyProvider();
    public override SigningCredentials GetSigningCredentials(ReadOnlySpan<byte> key) => throw new NotSupportedException();
}

internal sealed class DemoAsymmetricSignatureProvider : AsymmetricSignatureProviderBase
{
    // Unique demo provider name (built-in ECDSA/RSA use "ECDSA-P256-SHA256"/"RSA-2048-PKCS1-SHA256").
    public override string ProviderDescription => "Demo asymmetric signature provider for testing";
    private readonly string _signatureValue;
    public DemoAsymmetricSignatureProvider(string signatureValue)
        : base("DemoAsymSig") => _signatureValue = signatureValue;
    protected override string SignInternal(string value, ReadOnlySpan<byte> privateKey) => _signatureValue;
    protected override bool VerifyInternal(string value, string signature, ReadOnlySpan<byte> publicKey) => signature == _signatureValue;
    public override SigningCredentials GetSigningCredentials(ReadOnlySpan<byte> key, bool isKeyPrivate) => throw new NotSupportedException();
    public override IAsymmetricKeyProvider GetAsymmetricKeyProvider() => new DemoAsymmetricKeyProvider();
}

// Demo key providers (simplified)
internal sealed class DemoSymmetricKeyProvider : ISymmetricKeyProvider
{
    public byte[] CreateKey() => new byte[16];

    public bool IsKeyValid(ReadOnlySpan<byte> key) => key.Length > 0;
}

internal sealed class DemoAsymmetricKeyProvider : IAsymmetricKeyProvider
{
    public (byte[] PublicKey, byte[] PrivateKey) CreateKeys() => (new byte[8], new byte[8]);

    public bool IsKeyValid(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey) =>
        publicKey.Length > 0 && privateKey.Length > 0;
}
