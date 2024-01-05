namespace OtpAuth.DTOs;

public class OtpVerifyDto
{
    public required string Otp { get; set; }
    public required string OtpToken { get; set; }
}