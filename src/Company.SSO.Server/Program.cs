using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Company.SSO.Server.Data;
using Company.SSO.Server.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Register Database dynamically at the solution root directory
var dbPath = Path.Combine(builder.Environment.ContentRootPath, "shared.db");
var currentDir = new DirectoryInfo(builder.Environment.ContentRootPath);
while (currentDir != null)
{
    if (currentDir.GetFiles("Company.SSO.slnx").Any() || currentDir.GetFiles("Company.SSO.sln").Any())
    {
        dbPath = Path.Combine(currentDir.FullName, "shared.db");
        break;
    }
    currentDir = currentDir.Parent;
}

builder.Services.AddDbContext<SsoDbContext>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

// Register custom services
builder.Services.AddScoped<TokenService>();

// Configure SSO Server Cookie authentication (session cookie)
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = ".Company.SSO.Server.Session";
        options.LoginPath = "/Auth/Login";
        options.LogoutPath = "/Auth/Logout";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Cookie.SameSite = SameSiteMode.Lax;
    });

var app = builder.Build();

// Automatically ensure the database is created and seeded
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<SsoDbContext>();
    // EnsureCreated checks if database exists; if not, it creates database and runs seed data
    dbContext.Database.EnsureCreated();
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
