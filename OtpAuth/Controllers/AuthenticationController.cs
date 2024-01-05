using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OtpAuth.Data;
using OtpAuth.DTOs;
using OtpAuth.Interfaces;
using OtpAuth.Models;

namespace OtpAuth.Controllers;

[Route("Auth")]
public class AuthenticationController : ControllerBase
{
    private const int PhoneNumberLength = 10;
    private const int OtpExpiryMinutes = 5;
    private const int AccessTokenExpiryInDays = 30 * 6; // 6 months

    private readonly IOtpService _otpService;
    private readonly IJwtService _jwtService;
    private readonly DataContext _dataContext;

    public AuthenticationController(IOtpService otpService, IJwtService jwtService, DataContext dataContext)
    {
        _otpService = otpService ?? throw new ArgumentNullException(nameof(otpService));
        _jwtService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
        _dataContext = dataContext ?? throw new ArgumentNullException(nameof(dataContext));
    }

    [HttpPost]
    [Route("RequestOtp")]
    public string RequestOtp([FromBody] OtpRequestDto otpRequestDto)
    {
        ValidatePhone(otpRequestDto.Phone);
        var otp = _otpService.GenerateOtp();
        _otpService.SendOtp(otpRequestDto.Phone, otp);

        var claims = new[]
        {
            new Claim(ClaimTypes.Authentication, otp),
            new Claim(ClaimTypes.MobilePhone, otpRequestDto.Phone)
        };
        var jwe = _jwtService.GenerateToken(claims, TimeSpan.FromMinutes(OtpExpiryMinutes), true);
        return jwe;
    }

    [HttpPost]
    [Route("VerifyOtp")]
    public string VerifyOtp([FromBody] OtpVerifyDto otpVerifyDto)
    {
        if (string.IsNullOrWhiteSpace(otpVerifyDto.Otp) || string.IsNullOrWhiteSpace(otpVerifyDto.OtpToken))
        {
            throw new ValidationException("Otp or token should not be empty");
        }

        var claims = _jwtService.GetPrincipalFromToken(otpVerifyDto.OtpToken, true);
        var generatedOtp = claims.FindFirst(ClaimTypes.Authentication)?.Value;
        var phone = claims.FindFirst(ClaimTypes.MobilePhone)?.Value;
        if (string.IsNullOrWhiteSpace(phone) || string.IsNullOrWhiteSpace(generatedOtp))
        {
            throw new AuthenticationFailureException("Invalid Otp token");
        }

        if (otpVerifyDto.Otp != generatedOtp)
        {
            throw new AuthenticationFailureException("Incorrect Otp");
        }

        var user = _dataContext.Users.FirstOrDefault(user => user.PhoneNumber == phone);
        if (user == null)
        {
            user = new User()
            {
                PhoneNumber = phone,
                ReferenceId = Guid.NewGuid()
            };
            _dataContext.Add(user);
            _dataContext.SaveChanges();
        }

        var accessToken = CreateAccessToken(user.ReferenceId);
        return accessToken;
    }

    private void ValidatePhone(string phone)
    {
        if (string.IsNullOrWhiteSpace(phone))
        {
            throw new ValidationException("Phone should not be empty.");
        }

        if (!phone.All(char.IsDigit))
        {
            throw new ValidationException("Phone should be all digits.");
        }

        if (phone.Length != PhoneNumberLength)
        {
            throw new ValidationException($"Phone should be {PhoneNumberLength} digits long.");
        }
    }

    private string CreateAccessToken(Guid referenceId)
    {
        var accessTokenClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, referenceId.ToString())
        };
        var accessToken = _jwtService.GenerateToken(accessTokenClaims, TimeSpan.FromDays(AccessTokenExpiryInDays));
        return accessToken;
    }
}