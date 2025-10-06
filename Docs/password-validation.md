# Password Validation

Purpose: Simple configurable policy enforcement.

Options (PasswordValidationOptions):
- MinimumLength
- RequireUppercase
- RequireLowercase
- RequireDigit
- RequireNonAlphanumeric

Usage:
```csharp
var options = Options.Create(new PasswordValidationOptions { MinimumLength = 8 });
var validator = new PasswordValidationProvider(options);
var result = validator.ValidatePassword("Passw0rd!");
if (result.IsSuccess) { /* ok */ }
```
Result: `IsSuccess` plus `ValidationFailures` codes (order not guaranteed).

Demo: RunPasswordValidationDemo.