namespace Corely.Security.PasswordValidation.Models;

public record PasswordValidationOptions
{
    public const string NAME = "PasswordValidationOptions";

    public const int DEFAULT_MAXIMUM_LENGTH = 128;

    public int MinimumLength { get; init; } = 5;
    public int MaximumLength { get; init; } = DEFAULT_MAXIMUM_LENGTH;
    public bool RequireUppercase { get; init; } = true;
    public bool RequireLowercase { get; init; } = true;
    public bool RequireDigit { get; init; } = true;
    public bool RequireNonAlphanumeric { get; init; } = false;
}
