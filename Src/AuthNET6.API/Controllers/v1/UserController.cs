using AuthNET6.API.Attributes;
using AuthNET6.API.Models;
using AuthNET6.API.Security;
using AuthNET6.API.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace AuthNET6.API.Controllers.v1;

[Route("api/v1/users")]
public class UserController : CustomController
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenSecurity _tokenSecurity;

    public UserController(UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager, ITokenSecurity tokenSecurity)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenSecurity = tokenSecurity;
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> CreateUserAsync(CreateUserViewModel viewModel)
    {
        Validate(ModelState);

        if (HasNotifications) return BadRequest();

        var user = new ApplicationUser
        {
            UserName = viewModel.Email,
            Email = viewModel.Email
        };

        var identityResult = await _userManager.CreateAsync(user, viewModel.Password);

        if (!IsValidIdentityResult(identityResult)) return BadRequest();

        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var accessToken = _tokenSecurity.GenerateToken(user.Email);

        return Created(new { idUser = user.Id, code, accessToken });
    }

    [ApiKey]
    [HttpPost("login")]
    public async Task<IActionResult> LoginAsync(LoginViewModel viewModel)
    {
        Validate(ModelState);

        if (HasNotifications) return BadRequest();

        var user = await _userManager.FindByEmailAsync(viewModel.Email);

        if (user == null)
        {
            AddNotification("Invalid login");

            return BadRequest();
        }

        if (!user.EmailConfirmed)
        {
            AddNotification("Confirm your account");

            return BadRequest();
        }

        var signinResult = await _signInManager.PasswordSignInAsync(
            user, viewModel.Password, isPersistent: false, lockoutOnFailure: true);

        if (!signinResult.Succeeded)
        {
            AddNotification("Invalid login");

            return BadRequest();
        }

        var accessToken = _tokenSecurity.GenerateToken(viewModel.Email);

        return Ok(new { idUser = user.Id, accessToken });
    }

    [HttpGet("confirm-account")]
    public async Task<IActionResult> ConfirmAccountAsync(Guid idUser, string code, string token)
    {
        var isValidToken = _tokenSecurity.ValidateToken(token);

        if (!isValidToken)
        {
            AddNotification("Code invalid");

            return BadRequest();
        }

        if (HasNotifications) return BadRequest();

        var user = await _userManager.FindByIdAsync(idUser.ToString());

        if (user == null) return NotFound();

        var codeDecoded = WebEncoders.Base64UrlDecode(code);

        var identityResult = await _userManager.ConfirmEmailAsync(user, Encoding.UTF8.GetString(codeDecoded));

        if (!IsValidIdentityResult(identityResult)) return BadRequest();

        return NoContent();
    }

    [Authorize]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPasswordAsync(ForgotPasswordViewModel viewModel)
    {
        Validate(ModelState);

        if (HasNotifications) return BadRequest();

        var user = await _userManager.FindByEmailAsync(viewModel.Email);

        if (user == null) return NotFound();

        var code = await _userManager.GeneratePasswordResetTokenAsync(user);

        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        return Ok(new { idUser = user.Id, code });
    }

    [Authorize]
    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPasswordAsync(ResetPasswordViewModel viewModel)
    {
        Validate(ModelState);

        if (HasNotifications) return BadRequest();

        var user = await _userManager.FindByIdAsync(viewModel.IdUser.ToString());

        if (user == null) return NotFound();

        var codeDecoded = WebEncoders.Base64UrlDecode(viewModel.Code);

        var token = Encoding.UTF8.GetString(codeDecoded);

        var identityResult = await _userManager.ResetPasswordAsync(
            user, token, viewModel.Password);

        if (!IsValidIdentityResult(identityResult)) return BadRequest();

        return NoContent();
    }

    [Authorize]
    [HttpPut("change-password")]
    public async Task<IActionResult> ChangePasswordAsync(ChangePasswordViewModel viewModel)
    {
        Validate(ModelState);

        if (HasNotifications) return BadRequest();

        var user = await _userManager.FindByEmailAsync(viewModel.Email);

        if (user == null) return NotFound();

        var identityResult = await _userManager.ChangePasswordAsync(
            user, viewModel.CurrentPassword, viewModel.NewPassword);

        if (!IsValidIdentityResult(identityResult)) return BadRequest();

        return NoContent();
    }
}