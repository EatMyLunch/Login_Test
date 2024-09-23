using System.ComponentModel.DataAnnotations;

namespace Login_Test.Models
{
    public class Admin
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string Username { get; set; }
    }
}
