namespace AuthNET6.API.Security;

public interface ITokenSecurity
{
    string GenerateToken(string email);
    bool ValidateToken(string token);
}