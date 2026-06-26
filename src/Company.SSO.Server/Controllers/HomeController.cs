using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Company.SSO.Server.Data;
using Company.SSO.Server.Models;
using System.Diagnostics;
using System.Security.Claims;

namespace Company.SSO.Server.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly SsoDbContext _context;

    public HomeController(SsoDbContext context)
    {
        _context = context;
    }

    public async Task<IActionResult> Index()
    {
        var userEmail = User.FindFirstValue(ClaimTypes.Email);
        var currentUser = await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email == userEmail);

        if (currentUser == null)
        {
            return RedirectToAction("Logout", "Auth");
        }

        ViewBag.CurrentUser = currentUser;
        ViewBag.IsSuperAdmin = User.IsInRole("SuperAdmin") || currentUser.UserRoles.Any(ur => ur.Role.RoleName == "SuperAdmin");

        // Load dashboard stats
        ViewBag.Apps = await _context.Applications.ToListAsync();
        
        if (ViewBag.IsSuperAdmin)
        {
            ViewBag.Users = await _context.Users
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                .ToListAsync();
            
            ViewBag.Roles = await _context.Roles.ToListAsync();
            ViewBag.Permissions = await _context.Permissions.ToListAsync();
            ViewBag.AuditLogs = await _context.AuditLogs
                .OrderByDescending(al => al.Timestamp)
                .Take(50)
                .ToListAsync();
        }

        return View();
    }

    [HttpPost]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> RegisterApp(string name, string clientId, string clientSecret, string redirectUrl)
    {
        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(redirectUrl))
        {
            TempData["Error"] = "All application registration fields are required.";
            return RedirectToAction("Index");
        }

        var app = new Application
        {
            Name = name,
            ClientId = clientId,
            ClientSecret = clientSecret,
            RedirectUrl = redirectUrl,
            IsActive = true
        };

        _context.Applications.Add(app);
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserName = User.Identity?.Name ?? "Admin",
            Action = $"Admin Registered Application: {name} (Client ID: {clientId})",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });

        await _context.SaveChangesAsync();
        TempData["Success"] = $"Application '{name}' registered successfully!";

        return RedirectToAction("Index");
    }

    [HttpPost]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> AssignUserRole(int userId, int roleId)
    {
        var user = await _context.Users.FindAsync(userId);
        var role = await _context.Roles.FindAsync(roleId);

        if (user == null || role == null)
        {
            TempData["Error"] = "User or Role not found.";
            return RedirectToAction("Index");
        }

        // Clear existing roles first
        var currentRoles = await _context.UserRoles.Where(ur => ur.UserId == userId).ToListAsync();
        _context.UserRoles.RemoveRange(currentRoles);

        _context.UserRoles.Add(new UserRole { UserId = userId, RoleId = roleId });

        _context.AuditLogs.Add(new AuditLog
        {
            UserName = User.Identity?.Name ?? "Admin",
            Action = $"Admin Changed Role of User '{user.Email}' to '{role.RoleName}'",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });

        await _context.SaveChangesAsync();
        TempData["Success"] = $"Role of user '{user.Name}' changed to '{role.RoleName}'.";

        return RedirectToAction("Index");
    }

    [HttpGet]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> EditUser(int id)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
            .FirstOrDefaultAsync(u => u.Id == id);

        if (user == null)
        {
            TempData["Error"] = "User not found.";
            return RedirectToAction("Index");
        }

        ViewBag.Roles = await _context.Roles.ToListAsync();
        ViewBag.UserRoleIds = user.UserRoles.Select(ur => ur.RoleId).ToList();
        return View(user);
    }

    [HttpPost]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> EditUser(int id, string name, string email, string? mobile, string status, List<int> roleIds)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
            .FirstOrDefaultAsync(u => u.Id == id);

        if (user == null)
        {
            TempData["Error"] = "User not found.";
            return RedirectToAction("Index");
        }

        user.Name = name;
        user.Email = email;
        user.Mobile = mobile ?? string.Empty;
        user.Status = status;

        // Clear and add roles
        var currentRoles = await _context.UserRoles.Where(ur => ur.UserId == id).ToListAsync();
        _context.UserRoles.RemoveRange(currentRoles);

        if (roleIds != null)
        {
            foreach (var roleId in roleIds)
            {
                _context.UserRoles.Add(new UserRole { UserId = id, RoleId = roleId });
            }
        }

        _context.AuditLogs.Add(new AuditLog
        {
            UserName = User.Identity?.Name ?? "Admin",
            Action = $"Admin updated User Details & Roles for '{user.Email}'",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });

        await _context.SaveChangesAsync();
        TempData["Success"] = $"User '{user.Name}' updated successfully.";

        return RedirectToAction("Index");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View();
    }
}
