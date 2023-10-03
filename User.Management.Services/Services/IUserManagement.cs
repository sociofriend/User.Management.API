using User.Management.Services.Models.Authentication.SignUp;
using User.Management.Services.Models;
using User.Management.Services.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;
using User.Management.Services.Models.Authentication.Login;
namespace User.Management.Services.Services;

public interface IUserManagement
{
    public Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
    public Task<ApiResponse<List<string>>> AssignRoleRoUserAsync(List<string> roles, IdentityUser user);
    public Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel);
}