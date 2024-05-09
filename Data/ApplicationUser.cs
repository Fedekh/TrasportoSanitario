using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace TrasportoSanitario.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [StringLength(50, ErrorMessage = "Il campo {0} deve avere almeno {2} e al massimo {1} caratteri.", MinimumLength = 2)]
        public string Name { get; set; }

        [Required]
        [StringLength(50, ErrorMessage = "Il campo {0} deve avere almeno {2} e al massimo {1} caratteri.", MinimumLength = 2)]
        public string LastName { get; set; }

        public string? Address { get; set; }

        public bool IsActive { get; set; } = true;

        public override bool EmailConfirmed { get; set; } = true;
    }

}
