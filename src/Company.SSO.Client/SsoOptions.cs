namespace Company.SSO.Client;

public class SsoOptions
{
    public string SsoServerUrl { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string CookieName { get; set; } = string.Empty;
}
