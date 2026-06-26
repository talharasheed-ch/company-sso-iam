using System.ComponentModel.DataAnnotations;

namespace Company.SSO.Server.Models;

public class Permission
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    public string Code { get; set; } = string.Empty; // e.g. USER.CREATE, REPORT.VIEW

    public List<RolePermission> RolePermissions { get; set; } = new();
}
