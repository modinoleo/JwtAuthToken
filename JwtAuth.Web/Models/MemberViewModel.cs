namespace JwtAuth.Web.Models
{
    public class MemberViewModel
    {
        public IEnumerable<Member> Members { get; set; }
        public int MemberPerPage { get; set; }
        public int CurrentPage { get; set; }

        public int PageCount()
        {
            return Convert.ToInt32(Math.Ceiling((decimal)Members.Count() / (decimal)MemberPerPage));
        }
        public IEnumerable<Member> PaginatedBlogs()
        {
            int start = (CurrentPage - 1) * MemberPerPage;
            return Members.OrderBy(b => b.UserName).Skip(start).Take(MemberPerPage);
        }

    }
}
