using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Company.SSO.Client;

public class SsoCallbackMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SsoOptions _ssoOptions;

    public SsoCallbackMiddleware(RequestDelegate next, IOptions<SsoOptions> ssoOptions)
    {
        _next = next;
        _ssoOptions = ssoOptions.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var requestPath = context.Request.Path;

        // Front-Channel Single Log-Out (SLO) Interceptor
        if (requestPath.Equals("/signout-sso", StringComparison.OrdinalIgnoreCase))
        {
            var email = context.Request.Query["email"].ToString();
            
            // Authenticate the current context manually to inspect claims
            var authResult = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (authResult.Succeeded && authResult.Principal != null)
            {
                var currentUserEmail = authResult.Principal.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value 
                                       ?? authResult.Principal.FindFirst("email")?.Value;

                // Sign out only if no email hint is passed, or if it matches the current user
                if (string.IsNullOrEmpty(email) || 
                    (currentUserEmail != null && currentUserEmail.Equals(email, StringComparison.OrdinalIgnoreCase)))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            
            context.Response.ContentType = "image/gif";
            var bytes = Convert.FromBase64String("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");
            await context.Response.Body.WriteAsync(bytes);
            return;
        }

        var callbackPath = new Uri(_ssoOptions.RedirectUri).AbsolutePath;

        if (requestPath.Equals(callbackPath, StringComparison.OrdinalIgnoreCase))
        {
            var code = context.Request.Query["code"].ToString();
            var state = context.Request.Query["state"].ToString();

            if (string.IsNullOrEmpty(code))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Authorization code is missing.");
                return;
            }

            var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();
            using var httpClient = httpClientFactory.CreateClient();

            // Exchange authorization code for token
            var tokenRequestUrl = $"{_ssoOptions.SsoServerUrl.TrimEnd('/')}/api/auth/token";
            var requestBody = new Dictionary<string, string>
            {
                { "client_id", _ssoOptions.ClientId },
                { "client_secret", _ssoOptions.ClientSecret },
                { "code", code },
                { "grant_type", "authorization_code" },
                { "redirect_uri", _ssoOptions.RedirectUri }
            };

            var response = await httpClient.PostAsync(tokenRequestUrl, new FormUrlEncodedContent(requestBody));

            if (!response.IsSuccessStatusCode)
            {
                var errorResponse = await response.Content.ReadAsStringAsync();
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync($"Failed to exchange authorization code: {errorResponse}");
                return;
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid token response from SSO Server.");
                return;
            }

            // Parse and validate the JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(tokenResponse.AccessToken))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("SSO Access Token is not a valid JWT.");
                return;
            }

            var jwtToken = tokenHandler.ReadJwtToken(tokenResponse.AccessToken);

            // Extract claims
            var claims = jwtToken.Claims.ToList();

            // Save the tokens in the claims for local use (e.g. refreshing)
            claims.Add(new Claim("access_token", tokenResponse.AccessToken));
            if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
            {
                claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
            }

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = jwtToken.ValidTo
            };

            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProperties);

            // Redirect back to the original page or home
            var redirectUrl = string.IsNullOrEmpty(state) ? "/" : state;
            context.Response.Redirect(redirectUrl);
            return;
        }

        await _next(context);
    }
}

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}
