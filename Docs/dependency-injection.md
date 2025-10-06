# Dependency Injection

Factories and providers can be registered with standard .NET DI.

Example registration:
```csharp
services.AddSingleton<ISymmetricEncryptionProviderFactory>(_ =>
    new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE));
services.AddSingleton<IAsymmetricEncryptionProviderFactory>(_ =>
    new AsymmetricEncryptionProviderFactory(AsymmetricEncryptionConstants.RSA_CODE));
services.AddSingleton<IAsymmetricSignatureProviderFactory>(_ =>
    new AsymmetricSignatureProviderFactory(AsymmetricSignatureConstants.ECDSA_SHA256_CODE));
services.AddSingleton<IHashProviderFactory>(_ =>
    new HashProviderFactory(HashConstants.SALTED_SHA256_CODE));
services.AddScoped<IPasswordValidationProvider, PasswordValidationProvider>();
```
Options registration (manual example in demo):
```csharp
services.AddSingleton(_ => Options.Create(new PasswordValidationOptions { MinimumLength = 8 }));
```
Resolve and use:
```csharp
var hashFactory = provider.GetRequiredService<IHashProviderFactory>();
var hash = hashFactory.GetDefaultProvider().Hash("demo");
```
Note: Factories are light and stateful only for the provider registrations you add—singleton lifetime is appropriate.

Demo: RunDependencyInjectionDemo.