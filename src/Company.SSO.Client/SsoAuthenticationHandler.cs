using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace Company.SSO.Client;

public class SsoAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly SsoOptions _ssoOptions;

    public SsoAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IOptions<SsoOptions> ssoOptions)
        : base(options, logger, encoder)
    {
        _ssoOptions = ssoOptions.Value;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Authentication itself is managed by the Cookie scheme.
        // This handler only handles the challenge redirection.
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var returnUrl = properties.RedirectUri;
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = Context.Request.Path + Context.Request.QueryString;
        }

        var redirectUrl = $"{_ssoOptions.SsoServerUrl.TrimEnd('/')}/Auth/Login" +
                          $"?client_id={Uri.EscapeDataString(_ssoOptions.ClientId)}" +
                          $"&redirect_uri={Uri.EscapeDataString(_ssoOptions.RedirectUri)}" +
                          $"&state={Uri.EscapeDataString(returnUrl)}";

        Context.Response.Redirect(redirectUrl);
        return Task.CompletedTask;
    }
}
