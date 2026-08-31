namespace Corely.Security.PasswordValidation.Models;

public record PasswordValidationOptions
{
    public const string NAME = "PasswordValidationOptions";

    /// <summary>Default upper bound. Well above any real password, and low enough that a
    /// deliberately slow password hash cannot be turned into a denial-of-service vector by
    /// submitting a multi-megabyte input.</summary>
    public const int DEFAULT_MAXIMUM_LENGTH = 128;

    public int MinimumLength { get; init; } = 5;
    public int MaximumLength { get; init; } = DEFAULT_MAXIMUM_LENGTH;
    public bool RequireUppercase { get; init; } = true;
    public bool RequireLowercase { get; init; } = true;
    public bool RequireDigit { get; init; } = true;
    public bool RequireNonAlphanumeric { get; init; } = false;
}
