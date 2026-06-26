using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Company.SSO.Server.Data;
using Company.SSO.Server.Models;
using Company.SSO.Server.Services;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Company.SSO.Server.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthApiController : ControllerBase
{
    private readonly SsoDbContext _context;
    private readonly TokenService _tokenService;

    public AuthApiController(SsoDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
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
            Status = "Active",
            CreatedDate = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Assign default NormalUser role (RoleId = 3)
        var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "NormalUser");
        if (defaultRole != null)
        {
            _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = defaultRole.Id });
            await _context.SaveChangesAsync();
        }

        // Add Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            UserName = user.Email,
            Action = "User Registered via API",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });
        await _context.SaveChangesAsync();

        return Ok(new { message = "Registration successful." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());

        if (user == null || !PasswordHasher.VerifyPassword(request.Password, user.PasswordHash))
        {
            // Log failed attempt
            _context.AuditLogs.Add(new AuditLog
            {
                UserName = request.Email,
                Action = "Failed Login Attempt via API",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });
            await _context.SaveChangesAsync();

            return Unauthorized(new { message = "Invalid email or password." });
        }

        if (user.Status != "Active")
        {
            return BadRequest(new { message = $"Account is {user.Status}." });
        }

        // Load roles & permissions
        var roles = user.UserRoles.Select(ur => ur.Role.RoleName).ToList();
        var roleIds = user.UserRoles.Select(ur => ur.RoleId).ToList();
        var permissions = await _context.RolePermissions
            .Where(rp => roleIds.Contains(rp.RoleId))
            .Select(rp => rp.Permission.Code)
            .Distinct()
            .ToListAsync();

        var accessToken = _tokenService.GenerateAccessToken(user, roles, permissions);
        var refreshTokenString = _tokenService.GenerateRefreshToken();

        // Save refresh token
        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenString,
            Expiry = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            IsRevoked = false
        };

        _context.RefreshTokens.Add(refreshToken);

        // Add Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            UserName = user.Email,
            Action = "Login Successful via API",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });

        await _context.SaveChangesAsync();

        return Ok(new TokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshTokenString,
            TokenType = "Bearer",
            ExpiresIn = 3600
        });
    }

    // Handles the standard Back-channel code-to-token exchange (Form POST)
    [HttpPost("token")]
    public async Task<IActionResult> ExchangeToken([FromForm] TokenExchangeRequest request)
    {
        // 1. Validate Client Secrets
        var app = await _context.Applications.FirstOrDefaultAsync(a => a.ClientId == request.ClientId);
        if (app == null || app.ClientSecret != request.ClientSecret)
        {
            return Unauthorized(new { error = "invalid_client", error_description = "Invalid client credentials." });
        }

        if (!app.IsActive)
        {
            return BadRequest(new { error = "invalid_client", error_description = "Client application is inactive." });
        }

        // 2. Validate Code
        var authCode = await _context.AuthCodes
            .Include(c => c.User)
            .FirstOrDefaultAsync(c => c.Code == request.Code && c.ClientId == request.ClientId);

        if (authCode == null)
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Invalid or expired authorization code." });
        }

        if (authCode.Expiry < DateTime.UtcNow)
        {
            _context.AuthCodes.Remove(authCode);
            await _context.SaveChangesAsync();
            return BadRequest(new { error = "invalid_grant", error_description = "Authorization code is expired." });
        }

        // Load roles & permissions of user
        var user = authCode.User;
        var userRoles = await _context.UserRoles
            .Include(ur => ur.Role)
            .Where(ur => ur.UserId == user.Id)
            .ToListAsync();

        var roles = userRoles.Select(ur => ur.Role.RoleName).ToList();
        var roleIds = userRoles.Select(ur => ur.RoleId).ToList();
        var permissions = await _context.RolePermissions
            .Where(rp => roleIds.Contains(rp.RoleId))
            .Select(rp => rp.Permission.Code)
            .Distinct()
            .ToListAsync();

        var accessToken = _tokenService.GenerateAccessToken(user, roles, permissions);
        var refreshTokenString = _tokenService.GenerateRefreshToken();

        // 3. Save Refresh Token
        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenString,
            Expiry = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            IsRevoked = false
        };

        _context.RefreshTokens.Add(refreshToken);

        // Remove the temporary authorization code
        _context.AuthCodes.Remove(authCode);

        // Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            UserName = user.Email,
            Action = $"Token Issued for App: {app.Name}",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });

        await _context.SaveChangesAsync();

        return Ok(new TokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshTokenString,
            TokenType = "Bearer",
            ExpiresIn = 3600
        });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var existingToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

        if (existingToken == null || existingToken.IsRevoked || existingToken.Expiry < DateTime.UtcNow)
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Invalid, expired or revoked refresh token." });
        }

        // Token rotation: Revoke current token
        existingToken.IsRevoked = true;

        var user = existingToken.User;
        var userRoles = await _context.UserRoles
            .Include(ur => ur.Role)
            .Where(ur => ur.UserId == user.Id)
            .ToListAsync();

        var roles = userRoles.Select(ur => ur.Role.RoleName).ToList();
        var roleIds = userRoles.Select(ur => ur.RoleId).ToList();
        var permissions = await _context.RolePermissions
            .Where(rp => roleIds.Contains(rp.RoleId))
            .Select(rp => rp.Permission.Code)
            .Distinct()
            .ToListAsync();

        var newAccessToken = _tokenService.GenerateAccessToken(user, roles, permissions);
        var newRefreshTokenString = _tokenService.GenerateRefreshToken();

        // Add new refresh token
        var newRefreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = newRefreshTokenString,
            Expiry = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            IsRevoked = false
        };

        _context.RefreshTokens.Add(newRefreshToken);

        // Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            UserName = user.Email,
            Action = "Token Refreshed via API",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        });

        await _context.SaveChangesAsync();

        return Ok(new TokenResponseDto
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshTokenString,
            TokenType = "Bearer",
            ExpiresIn = 3600
        });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        var token = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);
        if (token != null)
        {
            token.IsRevoked = true;
            await _context.SaveChangesAsync();
        }

        return Ok(new { message = "Token revoked successfully." });
    }
}

// Request and DTO Classes
public class RegisterRequest
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? Mobile { get; set; }
    public string Password { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class TokenExchangeRequest
{
    [FromForm(Name = "client_id")]
    public string ClientId { get; set; } = string.Empty;

    [FromForm(Name = "client_secret")]
    public string ClientSecret { get; set; } = string.Empty;

    [FromForm(Name = "code")]
    public string Code { get; set; } = string.Empty;

    [FromForm(Name = "grant_type")]
    public string GrantType { get; set; } = string.Empty;

    [FromForm(Name = "redirect_uri")]
    public string RedirectUri { get; set; } = string.Empty;
}

public class RefreshTokenRequest
{
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
}

public class LogoutRequest
{
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
}

public class TokenResponseDto
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; } = 3600;
}
