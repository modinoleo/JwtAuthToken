namespace JwtAuth.Web.Models
{
    public class LoginResponse
    {
        public string UserName { get; set; }
        public string Access { get; set; }
        public string Token { get; set; }
        public DateTime? Expiration { get; set; }
    }
}
