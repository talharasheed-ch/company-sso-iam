using System.ComponentModel.DataAnnotations;

namespace Company.SSO.Server.Models;

public class AuditLog
{
    [Key]
    public int Id { get; set; }

    public int? UserId { get; set; }
    
    [Required]
    [MaxLength(150)]
    public string UserName { get; set; } = "System";

    [Required]
    public string Action { get; set; } = string.Empty;

    [MaxLength(50)]
    public string IpAddress { get; set; } = string.Empty;

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
