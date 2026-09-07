using Corely.Security.Encryption;
using Corely.Security.Encryption.Factories;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.Encryption.Providers;

public class SymmetricEncryptionProviderMismatchTests
{
    [Fact]
    public void Decrypt_SaysTheProviderIsWrong_WhenTheValueNamesAnother()
    {
        var keyStore = new InMemorySymmetricKeyStoreProvider(
            new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_GCM_CODE)
                .GetDefaultProvider()
                .GetSymmetricKeyProvider()
                .CreateKey()
        );

        var written = new SymmetricEncryptionProviderFactory(SymmetricEncryptionConstants.AES_CODE)
            .GetDefaultProvider()
            .Encrypt("secret", keyStore);

        var wrongProvider = new SymmetricEncryptionProviderFactory(
            SymmetricEncryptionConstants.AES_GCM_CODE
        ).GetDefaultProvider();

        var ex = Assert.Throws<EncryptionException>(() => wrongProvider.Decrypt(written, keyStore));

        // The point of the message: name both providers, so the reader does not go hunting the key.
        Assert.Contains(SymmetricEncryptionConstants.AES_CODE, ex.Message);
        Assert.Contains(SymmetricEncryptionConstants.AES_GCM_CODE, ex.Message);
    }
}
