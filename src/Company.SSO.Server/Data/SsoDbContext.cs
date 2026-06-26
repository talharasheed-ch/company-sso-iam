using Microsoft.EntityFrameworkCore;
using Company.SSO.Server.Models;
using Company.SSO.Server.Services;

namespace Company.SSO.Server.Data;

public class SsoDbContext : DbContext
{
    public SsoDbContext(DbContextOptions<SsoDbContext> options) : base(options) { }

    public DbSet<Application> Applications { get; set; } = null!;
    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Role> Roles { get; set; } = null!;
    public DbSet<Permission> Permissions { get; set; } = null!;
    public DbSet<UserRole> UserRoles { get; set; } = null!;
    public DbSet<RolePermission> RolePermissions { get; set; } = null!;
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    public DbSet<AuthCode> AuthCodes { get; set; } = null!;
    public DbSet<AuditLog> AuditLogs { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // UserRole Composite Key
        modelBuilder.Entity<UserRole>()
            .HasKey(ur => new { ur.UserId, ur.RoleId });

        modelBuilder.Entity<UserRole>()
            .HasOne(ur => ur.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ur => ur.UserId);

        modelBuilder.Entity<UserRole>()
            .HasOne(ur => ur.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ur => ur.RoleId);

        // RolePermission Composite Key
        modelBuilder.Entity<RolePermission>()
            .HasKey(rp => new { rp.RoleId, rp.PermissionId });

        modelBuilder.Entity<RolePermission>()
            .HasOne(rp => rp.Role)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.RoleId);

        modelBuilder.Entity<RolePermission>()
            .HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionId);

        // Seed Data
        // 1. Applications
        modelBuilder.Entity<Application>().HasData(
            new Application
            {
                Id = 1,
                Name = "ERP System (App 1)",
                ClientId = "app1_client_id",
                ClientSecret = "app1_client_secret",
                RedirectUrl = "http://localhost:5001/signin-sso",
                IsActive = true
            },
            new Application
            {
                Id = 2,
                Name = "CRM System (App 2)",
                ClientId = "app2_client_id",
                ClientSecret = "app2_client_secret",
                RedirectUrl = "http://localhost:5002/signin-sso",
                IsActive = true
            }
        );

        // 2. Roles
        modelBuilder.Entity<Role>().HasData(
            new Role { Id = 1, RoleName = "SuperAdmin" },
            new Role { Id = 2, RoleName = "ApplicationAdmin" },
            new Role { Id = 3, RoleName = "NormalUser" }
        );

        // 3. Permissions
        modelBuilder.Entity<Permission>().HasData(
            new Permission { Id = 1, Code = "USER.CREATE", Name = "Create User" },
            new Permission { Id = 2, Code = "USER.UPDATE", Name = "Update User" },
            new Permission { Id = 3, Code = "USER.DELETE", Name = "Delete User" },
            new Permission { Id = 4, Code = "REPORT.VIEW", Name = "View Reports" },
            new Permission { Id = 5, Code = "INVOICE.APPROVE", Name = "Approve Invoices" }
        );

        // 4. RolePermissions (Links)
        modelBuilder.Entity<RolePermission>().HasData(
            // SuperAdmin
            new RolePermission { RoleId = 1, PermissionId = 1 },
            new RolePermission { RoleId = 1, PermissionId = 2 },
            new RolePermission { RoleId = 1, PermissionId = 3 },
            new RolePermission { RoleId = 1, PermissionId = 4 },
            new RolePermission { RoleId = 1, PermissionId = 5 },
            
            // ApplicationAdmin
            new RolePermission { RoleId = 2, PermissionId = 1 },
            new RolePermission { RoleId = 2, PermissionId = 2 },
            new RolePermission { RoleId = 2, PermissionId = 4 },

            // NormalUser
            new RolePermission { RoleId = 3, PermissionId = 4 }
        );

        // 5. Users
        var adminPasswordHash = PasswordHasher.HashPassword("Admin@123");
        var userPasswordHash = PasswordHasher.HashPassword("User@123");

        modelBuilder.Entity<User>().HasData(
            new User
            {
                Id = 1,
                Name = "SSO Super Admin",
                Email = "admin@sso.company",
                PasswordHash = adminPasswordHash,
                Mobile = "+123456789",
                Status = "Active",
                CreatedDate = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new User
            {
                Id = 2,
                Name = "SSO Normal User",
                Email = "user@sso.company",
                PasswordHash = userPasswordHash,
                Mobile = "+987654321",
                Status = "Active",
                CreatedDate = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new User
            {
                Id = 3,
                Name = "SSO App Admin",
                Email = "appadmin@sso.company",
                PasswordHash = adminPasswordHash,
                Mobile = "+112233445",
                Status = "Active",
                CreatedDate = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            }
        );

        // 6. UserRoles (Links)
        modelBuilder.Entity<UserRole>().HasData(
            new UserRole { UserId = 1, RoleId = 1 }, // admin -> SuperAdmin
            new UserRole { UserId = 2, RoleId = 3 }, // user -> NormalUser
            new UserRole { UserId = 3, RoleId = 2 }  // appadmin -> ApplicationAdmin
        );
    }
}
