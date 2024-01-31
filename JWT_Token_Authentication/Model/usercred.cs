using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations;

namespace JWT_Token_Authentication.Model
{
    public class usercred
    {
        [Key]
        public int User_Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }

    }
}
