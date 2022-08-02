using System.ComponentModel.DataAnnotations;

namespace AuthNET6.API.ViewModels;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}