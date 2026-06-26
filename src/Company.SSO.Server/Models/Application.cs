using System.ComponentModel.DataAnnotations;

namespace Company.SSO.Server.Models;

public class Application
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string ClientSecret { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string RedirectUrl { get; set; } = string.Empty;

    public bool IsActive { get; set; } = true;
}
