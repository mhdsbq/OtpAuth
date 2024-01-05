using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using OtpAuth.Interfaces;

namespace OtpAuth.Services;

public class JwtService(IConfiguration configuration) : IJwtService
{
    private readonly string _key = configuration?["JwtSettings:Key"] ?? throw new ArgumentNullException();
    private readonly string _issuer = configuration?["JwtSettings:Issuer"] ?? throw new ArgumentNullException();
    private readonly string _audience = configuration?["JwtSettings:Audience"] ?? throw new ArgumentNullException();

    /// <inheritdoc />
    public string GenerateToken(IEnumerable<Claim> claims, TimeSpan expiry, bool useJwe = false)
    {
        var securityKey = new SymmetricSecurityKey(Convert.FromBase64String(_key));
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = signingCredentials,
            Issuer = _issuer,
            Audience = _audience,
            Expires = DateTime.UtcNow + expiry
        };

        if (useJwe)
        {
            tokenDescriptor.EncryptingCredentials = new EncryptingCredentials(securityKey, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512);
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <inheritdoc />
    public ClaimsPrincipal GetPrincipalFromToken(string token, bool isJwe = false)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentNullException(nameof(token));
        }

        var securityKey = new SymmetricSecurityKey(Convert.FromBase64String(_key));
        var validationParameters = new TokenValidationParameters
        {
            
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true
        };

        if (isJwe)
        {
            validationParameters.TokenDecryptionKey = securityKey;
        }

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            return claimsPrincipal;
        }
        catch
        {
            throw new AuthenticationException("Authentication failed.");
        }
    }
}