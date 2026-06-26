using System.ComponentModel.DataAnnotations;

namespace Company.SSO.Server.Models;

public class AuthCode
{
    [Key]
    [MaxLength(50)]
    public string Code { get; set; } = string.Empty;

    public int UserId { get; set; }
    public User User { get; set; } = null!;

    [Required]
    [MaxLength(50)]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string RedirectUrl { get; set; } = string.Empty;

    public DateTime Expiry { get; set; }
}
