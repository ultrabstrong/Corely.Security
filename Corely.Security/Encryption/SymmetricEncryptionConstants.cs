namespace Corely.Security.Encryption;

public static class SymmetricEncryptionConstants
{
    /// <summary>
    /// AES-CBC. Provides confidentiality only - ciphertext can be altered undetectably, and
    /// decryption failures are distinguishable, which is the shape a padding oracle attacks.
    /// Retained so existing data stays readable; prefer <see cref="AES_GCM_CODE"/> for new data.
    /// </summary>
    public const string AES_CODE = "AES-256-CBC-PKCS7";

    /// <summary>
    /// AES-GCM. Authenticated encryption: tampering is detected on decryption rather than
    /// producing garbage or a distinguishable padding error.
    /// </summary>
    public const string AES_GCM_CODE = "AES-256-GCM";
}
