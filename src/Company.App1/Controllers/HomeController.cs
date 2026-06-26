using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Company.SSO.Client;

namespace Company.App1.Controllers;

[Authorize]
public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [SsoPermission("REPORT.VIEW")]
    public IActionResult Reports()
    {
        return View();
    }

    [SsoPermission("INVOICE.APPROVE")]
    public IActionResult Invoices()
    {
        return View();
    }

    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }

    public async Task<IActionResult> Logout()
    {
        var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value 
                    ?? User.FindFirst("email")?.Value 
                    ?? string.Empty;

        // Sign out locally from App1
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Redirect to SSO Server logout to terminate the global SSO session
        var ssoServerUrl = "http://localhost:5000";
        var clientRedirect = "http://localhost:5001/";
        
        var logoutUrl = $"{ssoServerUrl}/Auth/Logout?email={Uri.EscapeDataString(email)}&redirect_uri={Uri.EscapeDataString(clientRedirect)}";
        return Redirect(logoutUrl);
    }
}
