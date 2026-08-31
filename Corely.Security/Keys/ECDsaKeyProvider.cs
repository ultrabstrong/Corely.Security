using System.Security.Cryptography;

namespace Corely.Security.Keys;

internal sealed class EcdsaKeyProvider : IAsymmetricKeyProvider
{
    public readonly ECCurve _ecCurve;

    public EcdsaKeyProvider()
    {
        _ecCurve = ECCurve.NamedCurves.nistP256;
    }

    public EcdsaKeyProvider(ECCurve curveType)
    {
        _ecCurve = curveType;
    }

    public (byte[] PublicKey, byte[] PrivateKey) CreateKeys()
    {
        using var ecdsa = ECDsa.Create(_ecCurve);
        return (ecdsa.ExportSubjectPublicKeyInfo(), ecdsa.ExportPkcs8PrivateKey());
    }

    public bool IsKeyValid(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        try
        {
            using var ecdsa = ECDsa.Create();

            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            if (!ecdsa.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(publicKey))
            {
                return false;
            }

            ecdsa.ImportPkcs8PrivateKey(privateKey, out _);
            return ecdsa.ExportPkcs8PrivateKey().AsSpan().SequenceEqual(privateKey);
        }
        catch
        {
            return false;
        }
    }
}
