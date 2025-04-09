using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;

public class JwtTokenService
{
    private readonly IConfiguration _configuration;

    public JwtTokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<string> GenerateTokenAsync(IdentityUser user, UserManager<IdentityUser> userManager)
    {
        // Fetch the settings from appsettings.json
        var secretKey = _configuration["Jwt:SecretKey"] ?? throw new ArgumentNullException("Jwt:SecretKey is not configured.");
        var issuer = _configuration["Jwt:Issuer"] ?? throw new ArgumentNullException("Jwt:Issuer is not configured.");
        var audience = _configuration["Jwt:Audience"] ?? throw new ArgumentNullException("Jwt:Audience is not configured.");

        // Create security key and credentials
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // Fetch roles for the user
        var roles = await userManager.GetRolesAsync(user);

        // Define claims for the token
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Add roles as claims
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        // Create and return the JWT
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1), // Use configuration for expiry if needed
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
