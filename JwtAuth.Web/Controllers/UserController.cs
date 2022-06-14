using JwtAuth.Web.Models;
using JwtAuth.Web.Services;
using JwtAuth.Web.Services.Helper;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuth.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private JwtAuthContext _context;
        private readonly ILogger<UserController> _logger;
        private readonly IConfiguration _configuration;
        private readonly UserManager<MemberRequestModel> _userManager;
        private readonly SignInManager<MemberRequestModel> _signInManager;
        private string generatedToken = null;
        private readonly ITokenService _tokenService;
        public UserController(ILogger<UserController> logger, ITokenService tokenService, JwtAuthContext context, IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
            _tokenService = tokenService;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost("Register")]
        public IActionResult Register([FromBody] MemberRequestModel member)
        {
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
        [HttpGet("Logout")]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return LocalRedirect(Url.Content("~/"));
        }
        [HttpPost("Login")]
        public IActionResult Login([FromForm] LoginRequest loginRequest)
        {
            //var hashedPassword = Encryption(loginRequest.Password);
            var user = _context.Members.FirstOrDefault(a => a.UserName == loginRequest.UserName);
            var returnUrl = Url.Content("~/");
            if (user == null) return NotFound();

            var isMatched = AuthenticationHelper.VerifyPassword(loginRequest.Password, user.Salt,user.Password);
            if (isMatched)
            {

                generatedToken = _tokenService.BuildToken(_configuration["Jwt:Key"].ToString(), _configuration["Jwt:Issuer"].ToString(), _configuration["Jwt:Audience"].ToString(), user);
                if (generatedToken != null)
                {
                    HttpContext.Session.SetString("Token", generatedToken);
                    //HttpContext.Session.SetString("EmailAddress", loginRequest.UserName);
                    return LocalRedirect(returnUrl);
                }
                else
                {
                    return (RedirectToAction("Error"));
                }
                //var tokenHandler = new JwtSecurityTokenHandler();
                //var key = Encoding.UTF8.GetBytes(_configuration["JWTKey"]);

                //var securityTokenDescriptor = new SecurityTokenDescriptor
                //{
                //    Subject = new ClaimsIdentity(new Claim[]
                //    {
                //        new Claim(ClaimTypes.NameIdentifier, loginRequest.UserName.ToString()),
                //        new Claim("Access", user?.Access)

                //    }),
                //    Expires = DateTime.UtcNow.AddMinutes(10000),
                //    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                //};
                //var token = tokenHandler.CreateToken(securityTokenDescriptor);
                //var response = new LoginResponse()
                //{
                //    UserName = loginRequest.UserName,
                //    Access = "Admin",
                //    Token = tokenHandler.WriteToken(token),
                //    Expiration = securityTokenDescriptor.Expires
                //};
                //FormsAuthentication.SetAuthCookie(model.Email, false);

                //var authTicket = new FormsAuthenticationTicket(1, user.Email, DateTime.Now, DateTime.Now.AddMinutes(20), false, user.Roles);
                //string encryptedTicket = FormsAuthentication.Encrypt(authTicket);
                //var authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
                //HttpContext.Response.Cookies.Add(authCookie);
                return RedirectToAction("Index", "Access");
                //return Ok(response);
            }
            return BadRequest();
        }
        //private HashSalt EncryptPassword2(string password)
        //{
        //    byte[] salt = new byte[128 / 8]; // Generate a 128-bit salt using a secure PRNG
        //    using (var rng = RandomNumberGenerator.Create())
        //    {
        //        rng.GetBytes(salt);
        //    }
        //    string encryptedPassw = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        //        password: password,
        //        salt: salt,
        //        prf: KeyDerivationPrf.HMACSHA1,
        //        iterationCount: 10000,
        //        numBytesRequested: 256 / 8
        //    ));
        //    return new HashSalt { Hash = encryptedPassw, Salt = salt };
        //}
        //private bool VerifyPassword(string enteredPassword, byte[] salt, string storedPassword)
        //{
        //    string encryptedPassw = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        //        password: enteredPassword,
        //        salt: salt,
        //        prf: KeyDerivationPrf.HMACSHA1,
        //        iterationCount: 10000,
        //        numBytesRequested: 256 / 8
        //    ));
        //    return encryptedPassw == storedPassword;
        //}
    }
}
