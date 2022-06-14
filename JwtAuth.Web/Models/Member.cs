using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace JwtAuth.Web.Models
{
    public partial class Member
    {
        [Key]
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        public int UserId { get; set; }
        public int? Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? MobileNo { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Code { get; set; }
        public bool IsVerified { get; set; }
        public byte[]? Salt { get; set; }
        public string? Role { get; set; }
    }
}
