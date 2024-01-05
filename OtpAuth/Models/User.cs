using System.ComponentModel.DataAnnotations;

namespace OtpAuth.Models;

public class User
{
    public int UserId { get; init; }
    [Required] public Guid ReferenceId { get; init; }
    [StringLength(250)] [Required] public string PhoneNumber { get; set; } = string.Empty;
}