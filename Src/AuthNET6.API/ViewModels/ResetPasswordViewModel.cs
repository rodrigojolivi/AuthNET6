using System.ComponentModel.DataAnnotations;

namespace AuthNET6.API.ViewModels;

public class ResetPasswordViewModel
{
    [Required]
    public Guid IdUser { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    public string Code { get; set; }
}