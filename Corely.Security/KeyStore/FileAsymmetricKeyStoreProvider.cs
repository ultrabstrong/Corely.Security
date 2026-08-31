namespace Corely.Security.KeyStore;

public class FileAsymmetricKeyStoreProvider : IAsymmetricKeyStoreProvider
{
    private const int ONLY_VERSION = 1;

    private readonly string _filePath;

    public FileAsymmetricKeyStoreProvider(string filePath)
    {
        _filePath = filePath;
    }

    public int GetCurrentVersion() => ONLY_VERSION;

    public (string PublicKey, string PrivateKey) Get(int version)
    {
        if (version != ONLY_VERSION)
        {
            throw new KeyStoreException(
                $"Key version {version} is invalid. {nameof(FileAsymmetricKeyStoreProvider)} holds "
                    + $"a single key pair at version {ONLY_VERSION} and does not support rotation."
            )
            {
                Reason = KeyStoreException.ErrorReason.InvalidVersion,
            };
        }

        return ReadKeys();
    }

    public (string PublicKey, string PrivateKey) GetCurrentKeys() => ReadKeys();

    private (string PublicKey, string PrivateKey) ReadKeys()
    {
        var keys = GetFileContents().Split(Environment.NewLine);

        if (keys.Length < 2)
        {
            throw new KeyStoreException(
                "Key file must contain a public key and a private key on separate lines."
            )
            {
                Reason = KeyStoreException.ErrorReason.CurrentKeyNotFound,
            };
        }

        return (keys[0], keys[1]);
    }

    protected virtual string GetFileContents() => File.ReadAllText(_filePath);
}
