using System.ComponentModel.DataAnnotations;

namespace TrasportoSanitario.Data.DTO
{
    public class UserLoginDTO
    {
        [Required]
        [StringLength(50, ErrorMessage = "Il campo {0} deve avere almeno {2} e al massimo {1} caratteri.", MinimumLength = 2)]
        [Display(Name = "Username")]
        public string Username { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = "";
        public bool RememberMe { get; set; } = true;
    }
}
