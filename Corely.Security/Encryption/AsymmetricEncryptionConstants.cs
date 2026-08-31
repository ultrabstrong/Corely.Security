namespace Corely.Security.Encryption;

public static class AsymmetricEncryptionConstants
{
    public const string RSA_CODE = "RSA-OAEP-SHA256";

    // The name this provider shipped under through 1.x. Key size comes from the key store at call
    // time, so "2048" was wrong for any other key. It is the prefix on every value encrypted by
    // 1.x, so it stays registered as a read alias - values written then still decrypt.
    public const string LEGACY_RSA_CODE = "RSA-2048-OAEP-SHA256";
}
