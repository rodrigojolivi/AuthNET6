using System.ComponentModel.DataAnnotations;

namespace AuthNET6.API.ViewModels;

public class ChangePasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    public string CurrentPassword { get; set; }

    [Required]
    public string NewPassword { get; set; }
}