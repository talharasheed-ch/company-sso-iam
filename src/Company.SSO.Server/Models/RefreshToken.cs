using System.ComponentModel.DataAnnotations;

namespace Company.SSO.Server.Models;

public class RefreshToken
{
    [Key]
    public int Id { get; set; }

    public int UserId { get; set; }
    public User User { get; set; } = null!;

    [Required]
    public string Token { get; set; } = string.Empty;

    public DateTime Expiry { get; set; }
    
    public DateTime Created { get; set; } = DateTime.UtcNow;

    public bool IsRevoked { get; set; }
}
