using Microsoft.AspNetCore.Identity;

namespace JwtAuth.Web.Models
{
    public class MemberRequestModel : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? MobileNo { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Code { get; set; }
    }
}
