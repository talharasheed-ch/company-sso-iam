using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Company.SSO.Server.Data;
using Company.SSO.Server.Models;
using Company.SSO.Server.Services;
using System.Security.Claims;

namespace Company.SSO.Server.Controllers;

public class AuthController : Controller
{
    private readonly SsoDbContext _context;

    public AuthController(SsoDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> Login(string? client_id, string? redirect_uri, string? state)
    {
        // Save the details to view bag so the login form can submit them
        ViewBag.ClientId = client_id;
        ViewBag.RedirectUri = redirect_uri;
        ViewBag.State = state;

        // SSO Magic: If user is already authenticated on the SSO server
        if (User.Identity?.IsAuthenticated == true)
        {
            if (!string.IsNullOrEmpty(client_id) && !string.IsNullOrEmpty(redirect_uri))
            {
                var userEmail = User.FindFirstValue(ClaimTypes.Email);
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);

                if (user != null && user.Status == "Active")
                {
                    // Generate Auth Code and redirect immediately
                    var authCode = await GenerateAndSaveAuthCode(user.Id, client_id, redirect_uri);
                    
                    var redirectUrl = $"{redirect_uri}?code={authCode}&state={Uri.EscapeDataString(state ?? string.Empty)}";
                    return Redirect(redirectUrl);
                }
            }

            // If they are logged in but just visited login directly, take them to the admin portal/dashboard
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string email, string password, string? client_id, string? redirect_uri, string? state)
    {
        ViewBag.ClientId = client_id;
        ViewBag.RedirectUri = redirect_uri;
        ViewBag.State = state;

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            ModelState.AddModelError("", "Email and password are required.");
            return View();
        }

        var user = await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email.ToLower() == email.ToLower());

        if (user == null || !PasswordHasher.VerifyPassword(password, user.PasswordHash))
        {
            _context.AuditLogs.Add(new AuditLog
            {
                UserName = email,
                Action = "Failed Web Login Attempt",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });
            await _context.SaveChangesAsync();

            ModelState.AddModelError("", "Invalid email or password.");
            return View();
        }

        if (user.Status != "Active")
        {
            ModelState.AddModelError("", $"Account is {user.Status}.");
            return View();
        }

        // Setup the local SSO Server session cookie
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(ClaimTypes.Email, user.Email),
        };

        foreach (var userRole in user.UserRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, userRole.Role.RoleName));
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        // Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            UserName = user.Email,
            Action = "Web Login Successful",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });
        await _context.SaveChangesAsync();

        // Redirect back to application if client_id and redirect_uri were provided
        if (!string.IsNullOrEmpty(client_id) && !string.IsNullOrEmpty(redirect_uri))
        {
            var authCode = await GenerateAndSaveAuthCode(user.Id, client_id, redirect_uri);
            var redirectUrl = $"{redirect_uri}?code={authCode}&state={Uri.EscapeDataString(state ?? string.Empty)}";
            return Redirect(redirectUrl);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(string name, string email, string password, string mobile)
    {
        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            ModelState.AddModelError("", "Name, Email and Password are required.");
            return View();
        }

        var exists = await _context.Users.AnyAsync(u => u.Email.ToLower() == email.ToLower());
        if (exists)
        {
            ModelState.AddModelError("", "Email is already registered.");
            return View();
        }

        var user = new User
        {
            Name = name,
            Email = email,
            Mobile = mobile ?? string.Empty,
            PasswordHash = PasswordHasher.HashPassword(password),
            Status = "Active",
            CreatedDate = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Assign Default Role (NormalUser)
        var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "NormalUser");
        if (defaultRole != null)
        {
            _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = defaultRole.Id });
            await _context.SaveChangesAsync();
        }

        // Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            UserName = user.Email,
            Action = "Web Registration Successful",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });
        await _context.SaveChangesAsync();

        // Automatically log in
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, "NormalUser")
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public async Task<IActionResult> Logout(string? email, string? redirect_uri)
    {
        var serverUserEmail = User.Identity?.IsAuthenticated == true ? User.FindFirstValue(ClaimTypes.Email) : null;

        // Only clear the SSO Server session cookie if the logged out user matches the active session
        if (string.IsNullOrEmpty(email) || 
            (serverUserEmail != null && serverUserEmail.Equals(email, StringComparison.OrdinalIgnoreCase)))
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            _context.AuditLogs.Add(new AuditLog
            {
                UserName = email ?? serverUserEmail ?? "Unknown",
                Action = "Web SignOut (Single Logout Executed)",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });
            await _context.SaveChangesAsync();
        }

        // Get all active apps to trigger their front-channel signouts via iframes
        var activeApps = await _context.Applications.Where(a => a.IsActive).ToListAsync();
        var signoutUrls = new List<string>();

        foreach (var app in activeApps)
        {
            try
            {
                var uri = new Uri(app.RedirectUrl);
                var signoutUrl = $"{uri.Scheme}://{uri.Authority}/signout-sso";
                if (!string.IsNullOrEmpty(email))
                {
                    signoutUrl += $"?email={Uri.EscapeDataString(email)}";
                }
                signoutUrls.Add(signoutUrl);
            }
            catch
            {
                // Skip if URI is invalid
            }
        }

        ViewBag.SignoutUrls = signoutUrls;
        ViewBag.RedirectUri = string.IsNullOrEmpty(redirect_uri) ? "/Auth/Login" : redirect_uri;

        return View();
    }

    private async Task<string> GenerateAndSaveAuthCode(int userId, string clientId, string redirectUri)
    {
        var code = Guid.NewGuid().ToString("N");
        var authCode = new AuthCode
        {
            Code = code,
            UserId = userId,
            ClientId = clientId,
            RedirectUrl = redirectUri,
            Expiry = DateTime.UtcNow.AddMinutes(5) // 5 minutes expiration
        };

        _context.AuthCodes.Add(authCode);
        await _context.SaveChangesAsync();
        return code;
    }
}
