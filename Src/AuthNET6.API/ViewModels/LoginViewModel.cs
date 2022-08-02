using System.ComponentModel.DataAnnotations;

namespace AuthNET6.API.ViewModels;

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }
}