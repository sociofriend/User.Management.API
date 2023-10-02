using Microsoft.AspNetCore.Identity;

namespace User.Management.Services.Models.Authentication.User;

public class CreateUserResponse
{
    public string Token { get; set; }
    public IdentityUser User { get; set; }
    public bool IsSuccess {get;set;}
}