using Microsoft.AspNetCore.Identity;

namespace User.Management.Services.Models.Authentication.Token;

public class CreateTokenResponse
{
    public string Token { get; set; } = null!;
    public DateTime Expiration { get; set; } 
    public IdentityUser User {get; set;} = null!;
}