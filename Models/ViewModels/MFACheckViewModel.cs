using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models.ViewModels
{
    public class MFACheckViewModel
    {
        [Required]
        public string Code { get; set; }
    }
}
