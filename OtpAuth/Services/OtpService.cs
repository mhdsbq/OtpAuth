using OtpAuth.Interfaces;

namespace OtpAuth.Services;

public class OtpService : IOtpService
{
    public string GenerateOtp()
    {
        var random = new Random();

        var otp = random.Next(100000, 999999).ToString();
        return otp;
    }

    public void SendOtp(string phone, string otp)
    {
        // USE YOUR SMS PROVIDER HERE
        Console.WriteLine($"Otp for {phone} is {otp}");
    }
}