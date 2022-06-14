using JwtAuth.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class MembersController : Controller
    {
        JwtAuthContext db = new JwtAuthContext();
  
        public IActionResult Index()
        {
            return View();
        }
        [HttpGet]
        [Authorize]

        public IActionResult GetMember(string searchString, string status, int pg = 1, int pageSize = 5)
        {
            ViewData["CurrentFilter"] = searchString;
            ViewData["status"] = status;

            IEnumerable<Member> members = new List<Member>();

            if (!String.IsNullOrEmpty(searchString))
            {
                members = db.Members.Where(s => s.UserName.Contains(searchString));
            }
            else
            {
                members = from l in db.Members select l;
            }

            var membersViewModel = new MemberViewModel
            {
                Members = members,
                MemberPerPage = 5,
                CurrentPage = pageSize
            };

            return View(membersViewModel);
        }
    }
}
