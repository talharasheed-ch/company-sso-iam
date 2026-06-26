using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Company.SSO.Server.Data;
using Company.SSO.Server.Models;
using Company.SSO.Server.Services;

namespace Company.SSO.Server.Controllers;

[ApiController]
[Route("api")]
public class AdminApiController : ControllerBase
{
    private readonly SsoDbContext _context;

    public AdminApiController(SsoDbContext context)
    {
        _context = context;
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .Select(u => new
            {
                u.Id,
                u.Name,
                u.Email,
                u.Mobile,
                u.Status,
                u.CreatedDate,
                Roles = u.UserRoles.Select(ur => ur.Role.RoleName).ToList()
            })
            .ToListAsync();

        return Ok(users);
    }

    [HttpPost("users/create")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var existingUser = await _context.Users.AnyAsync(u => u.Email.ToLower() == request.Email.ToLower());
        if (existingUser)
        {
            return BadRequest(new { message = "Email already registered." });
        }

        var user = new User
        {
            Name = request.Name,
            Email = request.Email,
            Mobile = request.Mobile ?? string.Empty,
            PasswordHash = PasswordHasher.HashPassword(request.Password),
            Status = request.Status ?? "Active",
            CreatedDate = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        if (request.RoleId > 0)
        {
            var role = await _context.Roles.FindAsync(request.RoleId);
            if (role != null)
            {
                _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
                await _context.SaveChangesAsync();
            }
        }

        // Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserName = "System Admin",
            Action = $"Admin Created User: {user.Email} (Role ID: {request.RoleId})",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });
        await _context.SaveChangesAsync();

        return Ok(new { message = "User created successfully.", userId = user.Id });
    }

    [HttpGet("permissions")]
    public async Task<IActionResult> GetPermissions()
    {
        var permissions = await _context.Permissions
            .Select(p => new
            {
                p.Id,
                p.Name,
                p.Code
            })
            .ToListAsync();

        return Ok(permissions);
    }

    [HttpPost("permissions/assign")]
    public async Task<IActionResult> AssignPermission([FromBody] AssignPermissionRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        // Case 1: Assign Role to User
        if (request.UserId > 0 && request.RoleId > 0)
        {
            var user = await _context.Users.FindAsync(request.UserId);
            var role = await _context.Roles.FindAsync(request.RoleId);

            if (user == null || role == null)
            {
                return NotFound(new { message = "User or Role not found." });
            }

            var exists = await _context.UserRoles.AnyAsync(ur => ur.UserId == request.UserId && ur.RoleId == request.RoleId);
            if (!exists)
            {
                _context.UserRoles.Add(new UserRole { UserId = request.UserId, RoleId = request.RoleId });
                
                _context.AuditLogs.Add(new AuditLog
                {
                    UserName = "System Admin",
                    Action = $"Assigned Role '{role.RoleName}' to User '{user.Email}'",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
                
                await _context.SaveChangesAsync();
            }

            return Ok(new { message = "Role assigned successfully." });
        }

        // Case 2: Assign Permission to Role
        if (request.RoleId > 0 && request.PermissionId > 0)
        {
            var role = await _context.Roles.FindAsync(request.RoleId);
            var permission = await _context.Permissions.FindAsync(request.PermissionId);

            if (role == null || permission == null)
            {
                return NotFound(new { message = "Role or Permission not found." });
            }

            var exists = await _context.RolePermissions.AnyAsync(rp => rp.RoleId == request.RoleId && rp.PermissionId == request.PermissionId);
            if (!exists)
            {
                _context.RolePermissions.Add(new RolePermission { RoleId = request.RoleId, PermissionId = request.PermissionId });
                
                _context.AuditLogs.Add(new AuditLog
                {
                    UserName = "System Admin",
                    Action = $"Assigned Permission '{permission.Code}' to Role '{role.RoleName}'",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
                
                await _context.SaveChangesAsync();
            }

            return Ok(new { message = "Permission assigned successfully." });
        }

        return BadRequest(new { message = "Invalid parameters. Provide either (UserId and RoleId) or (RoleId and PermissionId)." });
    }
}

public class CreateUserRequest
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? Mobile { get; set; }
    public string? Status { get; set; }
    public int RoleId { get; set; }
}

public class AssignPermissionRequest
{
    public int UserId { get; set; }
    public int RoleId { get; set; }
    public int PermissionId { get; set; }
}
