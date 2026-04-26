namespace Corely.Security.Secrets;

public interface ISecretProvider
{
    string CreateSecret();

    bool IsSecretValid(string secret);
}
