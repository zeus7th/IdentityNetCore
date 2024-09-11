using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models.ViewModels
{
    public class SigninViewModel
    {
        [Required(ErrorMessage ="User Name must be provided")]
        [DataType(DataType.EmailAddress)]
        public string Username { get; set; }
        [Required(ErrorMessage = "Password must be provided")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
