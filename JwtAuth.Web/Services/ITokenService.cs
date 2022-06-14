using JwtAuth.Web.Models;

namespace JwtAuth.Web.Services
{
    public interface ITokenService
    {
        string BuildToken(string key, string issuer, string audience, Member member);
        //string GenerateJSONWebToken(string key, string issuer, UserDTO user);
        bool IsTokenValid(string key, string issuer, string token);
    }
}
