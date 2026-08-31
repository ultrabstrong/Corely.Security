namespace Corely.Security.Signature;

public static class AsymmetricSignatureConstants
{
    public const string ECDSA_SHA256_CODE = "ECDSA-SHA256";
    public const string RSA_SHA256_CODE = "RSA-PKCS1-SHA256";

    // Names these providers shipped under through 1.x. The curve and modulus size they claimed
    // come from whichever key the key store supplies, not from provider configuration, so they
    // were wrong for any other key. Registered as read aliases: signatures carry no prefix, so
    // nothing stored depends on them, but code and configuration referencing them still resolves.
    public const string LEGACY_ECDSA_SHA256_CODE = "ECDSA-P256-SHA256";
    public const string LEGACY_RSA_SHA256_CODE = "RSA-2048-PKCS1-SHA256";
}
