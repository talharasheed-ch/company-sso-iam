using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

namespace Company.SSO.Client;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public class SsoPermissionAttribute : Attribute, IAsyncAuthorizationFilter
{
    public string Permission { get; }

    public SsoPermissionAttribute(string permission)
    {
        Permission = permission;
    }

    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;

        if (user == null || user.Identity?.IsAuthenticated != true)
        {
            context.Result = new ChallengeResult();
            return Task.CompletedTask;
        }

        // Check if the user has the required permission code
        var hasPermission = user.Claims
            .Any(c => (c.Type == "permission" || c.Type == "permissions" || c.Type == "Permission") && 
                      c.Value.Equals(Permission, StringComparison.OrdinalIgnoreCase));

        // Super Admins can bypass permission checks (optional but useful)
        var isSuperAdmin = user.Claims.Any(c => (c.Type == ClaimTypes.Role || c.Type == "role") && 
                                                c.Value.Equals("SuperAdmin", StringComparison.OrdinalIgnoreCase));

        if (!hasPermission && !isSuperAdmin)
        {
            context.Result = new ForbidResult();
        }

        return Task.CompletedTask;
    }
}

public static class ClaimsPrincipalExtensions
{
    public static bool HasSsoPermission(this ClaimsPrincipal user, string permission)
    {
        if (user == null || user.Identity?.IsAuthenticated != true) return false;
        
        var isSuperAdmin = user.Claims.Any(c => (c.Type == ClaimTypes.Role || c.Type == "role") && 
                                                c.Value.Equals("SuperAdmin", StringComparison.OrdinalIgnoreCase));
        if (isSuperAdmin) return true;

        return user.Claims.Any(c => (c.Type == "permission" || c.Type == "permissions" || c.Type == "Permission") && 
                                     c.Value.Equals(permission, StringComparison.OrdinalIgnoreCase));
    }
}
