using System.ComponentModel.DataAnnotations;

namespace AuthNET6.API.ViewModels;

public class ConfirmAccountViewModel
{
    [Required]
    public Guid IdUser { get; set; }

    [Required]
    public string Token { get; set; }
}