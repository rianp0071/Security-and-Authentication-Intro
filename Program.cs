// Import required namespaces
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using MyApp.Helpers;
using MyApp.Data;


var builder = WebApplication.CreateBuilder(args);

// Step 1: Configure In-Memory Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase("AppDb"));

// Step 2: Add Identity Services
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Step 3: Configure JWT Authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        var secretKey = builder.Configuration.GetValue<string>("Jwt:SecretKey")
                        ?? throw new InvalidOperationException("JWT Secret Key is not configured.");
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
        };
    });

builder.Services.AddTransient<JwtTokenService>();


// Step 4: Add Authorization Policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserPolicy", policy => policy.RequireRole("User"));
    options.AddPolicy("GuestPolicy", policy => policy.RequireRole("Guest"));
});

var app = builder.Build();

// Step 5: Initialize Roles on Startup
await InitializeRolesAsync(app);

async Task InitializeRolesAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var roles = new[] { "Admin", "User", "Guest" };

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            var result = await roleManager.CreateAsync(new IdentityRole(role));
            if (!result.Succeeded)
            {
                throw new Exception($"Failed to create role: {role}. Errors: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }
    }
}

// Step 6: Define Endpoints

// User registration endpoint
app.MapPost("/register", async (
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    RegisterRequest request) =>
{
    if (!ValidationHelpers.IsValidInput(request.Email, "@.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"))
    {
        return Results.BadRequest("Invalid email format.");
    }

    if (!ValidationHelpers.IsValidInput(request.Password, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-!@#$%^&*()_+={}[]|:;\"'<>,.?/"))
    {
        return Results.BadRequest("Invalid password format.");
    }

    if (!ValidationHelpers.IsValidInput(request.Role, "Admin,User,Guest"))
    {
        return Results.BadRequest("Invalid role format.");
    }

    if (!XssHelpers.IsValidXSSInput(request.Email))
    {
        return Results.BadRequest("XSS attack detected in email.");
    }
    
    if (!XssHelpers.IsValidXSSInput(request.Password))
    {
        return Results.BadRequest("XSS attack detected in password.");
    }
    
    if (!XssHelpers.IsValidXSSInput(request.Role))
    {
        return Results.BadRequest("XSS attack detected in role.");
    }

    var allowedRoles = new[] { "Admin", "User", "Guest" };
    if (!allowedRoles.Contains(request.Role))
    {
        return Results.BadRequest("Invalid role. Allowed roles are: Admin, User, Guest.");
    }

    var user = new IdentityUser
    {
        UserName = request.Email,
        Email = request.Email
    };

    var result = await userManager.CreateAsync(user, request.Password);
    if (result.Succeeded)
    {
        if (!await roleManager.RoleExistsAsync(request.Role))
        {
            await roleManager.CreateAsync(new IdentityRole(request.Role));
        }
        await userManager.AddToRoleAsync(user, request.Role);
        return Results.Ok("User registered and assigned role successfully!");
    }

    return Results.BadRequest(result.Errors);
});


app.MapPost("/login", async (
    UserManager<IdentityUser> userManager,
    JwtTokenService jwtTokenService,
    LoginRequest request) =>
{
    // var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    //                       ?? throw new InvalidOperationException("DefaultConnection is not configured.");
    // var LoginHelper = new LoginHelper(connectionString);

    if (!ValidationHelpers.IsValidInput(request.Email, "@.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"))
    {
        return Results.BadRequest("Invalid email format.");
    }

    if (!ValidationHelpers.IsValidInput(request.Password, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-!@#$%^&*()_+={}[]|:;\"'<>,.?/"))
    {
        return Results.BadRequest("Invalid password format.");
    }

    if (!XssHelpers.IsValidXSSInput(request.Email))
    {
        return Results.BadRequest("XSS attack detected in email.");
    }

    if (!XssHelpers.IsValidXSSInput(request.Password))
    {
        return Results.BadRequest("XSS attack detected in password.");
    }


    
    var user = await userManager.FindByNameAsync(request.Email);
    if (user != null && await userManager.CheckPasswordAsync(user, request.Password))
    {
        // Generate token including roles
        var token = await jwtTokenService.GenerateTokenAsync(user, userManager);
        return Results.Ok(new { Token = token });
    }

    return Results.Unauthorized();
});

// Unprotected route
app.MapGet("/", () => "Welcome to the API!");

// Protected routes
app.MapGet("/protected", () => "You have accessed a protected route!")
    .RequireAuthorization();

app.MapGet("/admin", () => "Welcome, Admin!")
    .RequireAuthorization("AdminPolicy");

app.MapGet("/user", () => "Welcome, User!")
    .RequireAuthorization("UserPolicy");

app.MapGet("/guest", () => "Welcome, Guest!")
    .RequireAuthorization("GuestPolicy");

// Run the application
app.Run();

// Step 7: Define Supporting Classes
public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
}



