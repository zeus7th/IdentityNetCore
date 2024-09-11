using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models.ViewModels
{
    public class MFAViewModel
    {
        [Required]
        public string Token { get; set; }
        public string Code {  get; set; }
        public string QRCodeUrl { get; set; }
    }
}
