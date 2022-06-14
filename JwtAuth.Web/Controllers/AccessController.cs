using JwtAuth.Web.Models;
using JwtAuth.Web.Services.Helper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace JwtAuth.Web.Controllers
{
 
    [Route("api/[controller]")]
    [ApiController]
    public class AccessController : Controller
    {
        private JwtAuthContext _context;
        private readonly ILogger<UserController> _logger;
        public AccessController(ILogger<UserController> logger,  JwtAuthContext context)
        {
            _context = context;
            _logger = logger;
        }
        [AllowAnonymous]
        //[Authorize]
        public IActionResult Index()
        {
            return View();
        }
        [Authorize]
        [HttpPost("SignUp")]
        public ActionResult SignUp([FromForm] Member member)
        {
            var test = HttpContext.User.Identity.Name;
            var hashSalt = AuthenticationHelper.PasswordEncrypt(member.Password);
            var _member = new Member()
            {
                FirstName = member.FirstName,
                LastName = member.LastName,
                Password = hashSalt.Hash,
                Salt = hashSalt.Salt,
                Email = member.Email,
                UserName = member.UserName,
                Code = member.Code,
                MobileNo = member.MobileNo,
                Id = 0,
                IsVerified = true
            };
            _context.Members.Add(_member);
            _context.SaveChanges();
            return Ok();

        }
       
    }
}
