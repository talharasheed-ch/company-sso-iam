using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Company.App2.Controllers;

[Authorize]
public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    public async Task<IActionResult> Logout()
    {
        var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value 
                    ?? User.FindFirst("email")?.Value 
                    ?? string.Empty;

        // Sign out locally from App2
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Redirect to SSO Server logout to terminate the global SSO session
        var ssoServerUrl = "http://localhost:5000";
        var clientRedirect = "http://localhost:5002/";
        
        var logoutUrl = $"{ssoServerUrl}/Auth/Logout?email={Uri.EscapeDataString(email)}&redirect_uri={Uri.EscapeDataString(clientRedirect)}";
        return Redirect(logoutUrl);
    }
}
