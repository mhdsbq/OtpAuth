using System.Security.Authentication;
using System.Security.Claims;

namespace OtpAuth.Interfaces;

public interface IJwtService
{
    /// <summary>
    /// Generate a jwt token with provided claims and expiry.
    /// </summary>
    /// <param name="claims"> List of claims to include in the token. </param>
    /// <param name="expiry"> Time span to expiry. </param>
    /// <param name="useJwe"> Set to true to create JWE instead of JWT. false by default. </param>
    /// <returns> Returns the generated jwt token. </returns>
    string GenerateToken(IEnumerable<Claim> claims, TimeSpan expiry, bool useJwe = false);

    /// <summary>
    /// Validates a jwt token and returns the attached claims.
    /// </summary>
    /// <param name="token"> Jwt token to be validated.</param>
    /// <param name="isJwe"> Set to true if the token is JWE. false by default. </param>
    /// <returns> Claims retrieved from the token.</returns>
    /// <exception cref="AuthenticationException"> is thrown if token is invalid or expired.</exception>;
    ClaimsPrincipal GetPrincipalFromToken(string token, bool isJwe = false);
}