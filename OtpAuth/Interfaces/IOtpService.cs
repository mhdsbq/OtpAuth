namespace OtpAuth.Interfaces;

public interface IOtpService
{
    /// <summary>
    /// Generate 6 digit random otp
    /// </summary>
    /// <returns> 6 digit rando otp as a string. </returns>
    public string GenerateOtp();
    
    /// <summary>
    /// Send otp SMS using SMS provider API.
    /// </summary>
    /// <param name="phone"> Phone number to which OTP has to be sent. </param>
    /// <param name="otp"> OTP. </param>
    public void SendOtp(string phone, string otp);
}