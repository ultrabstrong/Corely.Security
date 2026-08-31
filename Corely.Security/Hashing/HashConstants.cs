namespace Corely.Security.Hashing;

public static class HashConstants
{
    public const string SALTED_SHA256_CODE = "SHA256-Salted";
    public const string SALTED_SHA512_CODE = "SHA512-Salted";

    /// <summary>
    /// PBKDF2-HMAC-SHA256. The only provider here suitable for user-chosen passwords: the salted
    /// SHA providers are single-round and therefore fast, which is the opposite of what password
    /// storage needs.
    /// </summary>
    public const string PBKDF2_SHA256_CODE = "PBKDF2-SHA256";
}
