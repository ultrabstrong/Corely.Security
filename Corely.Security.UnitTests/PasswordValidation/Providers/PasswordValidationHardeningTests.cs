using Corely.Security.Password;
using Corely.Security.PasswordValidation.Models;
using Corely.Security.PasswordValidation.Providers;
using Microsoft.Extensions.Options;

namespace Corely.Security.UnitTests.PasswordValidation.Providers;

/// <summary>
/// An upper bound matters more now that password hashing is deliberately slow: without one, an
/// arbitrarily long submitted password turns the work factor into a denial-of-service lever.
/// </summary>
public class PasswordValidationHardeningTests
{
    private static PasswordValidationProvider CreateProvider(
        PasswordValidationOptions? options = null
    ) => new(Options.Create(options ?? new PasswordValidationOptions()));

    [Fact]
    public void ValidatePassword_Throws_WithNullPassword()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentNullException>(() => provider.ValidatePassword(null!));
    }

    [Fact]
    public void DefaultMaximumLength_IsBounded()
    {
        Assert.Equal(128, PasswordValidationOptions.DEFAULT_MAXIMUM_LENGTH);
        Assert.Equal(
            PasswordValidationOptions.DEFAULT_MAXIMUM_LENGTH,
            new PasswordValidationOptions().MaximumLength
        );
    }

    [Fact]
    public void ValidatePassword_Fails_WhenPasswordExceedsMaximumLength()
    {
        var provider = CreateProvider(
            new PasswordValidationOptions { MinimumLength = 5, MaximumLength = 20 }
        );

        var result = provider.ValidatePassword("Abcdefg1" + new string('x', 50));

        Assert.False(result.IsSuccess);
        Assert.Contains(PasswordValidationConstants.PASSWORD_TOO_LONG, result.ValidationFailures);
    }

    [Fact]
    public void ValidatePassword_Succeeds_AtExactlyMaximumLength()
    {
        var provider = CreateProvider(
            new PasswordValidationOptions { MinimumLength = 5, MaximumLength = 12 }
        );

        var result = provider.ValidatePassword("Abcdefgh123!");

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void ValidatePassword_Succeeds_AtExactlyMinimumLength()
    {
        var provider = CreateProvider(
            new PasswordValidationOptions { MinimumLength = 8, MaximumLength = 64 }
        );

        var result = provider.ValidatePassword("Abcdefg1");

        Assert.True(result.IsSuccess);
    }

    /// <summary>
    /// Previously the pattern rejected any password containing a line break while the detailed
    /// pass found nothing wrong, yielding an invalid result with an empty failure list - the user
    /// would be told no more than "invalid".
    /// </summary>
    [Fact]
    public void ValidatePassword_WithANewline_ReportsAReasonOrPasses()
    {
        var provider = CreateProvider(
            new PasswordValidationOptions { MinimumLength = 5, MaximumLength = 64 }
        );

        var result = provider.ValidatePassword("Abc1\ndefg");

        Assert.True(
            result.IsSuccess || result.ValidationFailures.Length > 0,
            "An invalid password must always come with at least one stated reason."
        );
    }

    [Fact]
    public void ValidatePassword_TooShort_ReportsAReason()
    {
        var provider = CreateProvider(new PasswordValidationOptions { MinimumLength = 10 });

        var result = provider.ValidatePassword("Ab1");

        Assert.False(result.IsSuccess);
        Assert.Contains(PasswordValidationConstants.PASSWORD_TOO_SHORT, result.ValidationFailures);
    }
}
