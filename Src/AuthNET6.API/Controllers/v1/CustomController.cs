using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AuthNET6.API.Controllers.v1;

[ApiController]
public class CustomController : ControllerBase
{
    protected List<string> Notifications;

    protected bool HasNotifications;

    public CustomController()
    {
        Notifications = new List<string>();
    }

    protected void Validate(ModelStateDictionary modelState)
    {
        if (modelState.IsValid) return;

        Notifications = ModelState.Values.SelectMany(x => x.Errors.Select(x => x.ErrorMessage)).ToList();

        HasNotifications = true;
    }

    protected bool IsValidIdentityResult(IdentityResult identityResult)
    {
        if (identityResult.Succeeded) return true;

        var notifications = identityResult.Errors.Select(x => x.Description);

        AddNotification(notifications);

        return false;

    }

    protected void AddNotification(string notification)
    {
        Notifications.Add(notification);
    }

    protected void AddNotification(IEnumerable<string> notifications)
    {
        Notifications.AddRange(notifications);
    }

    protected new IActionResult Ok(object data)
    {
        return base.Ok(new { createdAt = DateTime.Now, message = "Success", data });
    }

    protected IActionResult Created(object data)
    {
        return base.Created("", new { createdAt = DateTime.Now, message = "Success", data });
    }

    protected new IActionResult BadRequest()
    {
        return base.BadRequest(new { createdAt = DateTime.Now, message = "Error", notifications = Notifications });
    }
}