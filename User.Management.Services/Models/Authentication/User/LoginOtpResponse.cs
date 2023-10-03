using Microsoft.AspNetCore.Identity;

namespace User.Management.Services.Models.Authentication.User;

public class LoginOtpResponse
{
    public string Token { get; set; } = null!;
    public bool IsTwoFactorEnabled { get; set; }  
    public IdentityUser User { get; set; } = null!; 
}