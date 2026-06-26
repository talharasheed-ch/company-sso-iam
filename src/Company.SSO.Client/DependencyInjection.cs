using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Company.SSO.Client;

public static class DependencyInjection
{
    public static IServiceCollection AddSSO(this IServiceCollection services, Action<SsoOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddHttpClient();

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = "SSO";
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddScheme<AuthenticationSchemeOptions, SsoAuthenticationHandler>("SSO", null);

        // Dynamically configure cookie options using configured SSO options to avoid Building Service Provider early
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<IOptions<SsoOptions>>((cookieOptions, ssoOptionsOpt) =>
            {
                var ssoOptions = ssoOptionsOpt.Value;
                cookieOptions.Cookie.Name = string.IsNullOrEmpty(ssoOptions.CookieName) 
                    ? $".Company.SSO.Client.{ssoOptions.ClientId}" 
                    : ssoOptions.CookieName;
                
                cookieOptions.Cookie.HttpOnly = true;
                cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                cookieOptions.Cookie.SameSite = SameSiteMode.Lax;
                cookieOptions.AccessDeniedPath = "/Home/AccessDenied";

                cookieOptions.Events = new CookieAuthenticationEvents
                {
                    OnRedirectToLogin = context =>
                    {
                        return context.HttpContext.ChallengeAsync("SSO");
                    }
                };
            });

        return services;
    }

    public static IApplicationBuilder UseSSO(this IApplicationBuilder app)
    {
        app.UseMiddleware<SsoCallbackMiddleware>();
        return app;
    }
}
