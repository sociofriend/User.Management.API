using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using User.Management.Services.Models;
using User.Management.Services.Models.Authentication.User;
using User.Management.Services.Models.Authentication.SignUp;


namespace User.Management.Services.Services;

public class UserManagement : IUserManagement
{

    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    public IConfiguration _configuration { get; }


    public UserManagement(UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<IdentityUser> signInManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
    {
        //check user exists
        var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
        if (userExists != null)
        {
            return new ApiResponse<CreateUserResponse>
            {
                IsSuccess = false,
                StatusCode = 403,
                Message = "User already exists."
            };
        }

        //if user does not exist, add user in the database
        IdentityUser user = new()
        {
            Email = registerUser.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = registerUser.Username,
            TwoFactorEnabled = bool.Parse(_configuration["UserSettings:TwoFactorEnabled"]!)
        };


        var result = await _userManager.CreateAsync(user, registerUser.Password); //bring changes to DB and will save changes
        if (result.Succeeded)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            return new ApiResponse<CreateUserResponse>
            {
                IsSuccess = true,
                Response = new CreateUserResponse
                {
                    User = user,
                    Token = token,
                    IsSuccess = true
                }
            };
        }
        else
        {
            return new ApiResponse<CreateUserResponse>
            {
                IsSuccess = false,
                StatusCode = 500,
                Message = "User not created."
            };
        }
    }

    public async Task<ApiResponse<List<string>>> AssignRoleRoUserAsync(List<string> roles, IdentityUser user)
    {
        var assignedRoles = new List<string>();

        foreach (var role in roles)
        {
            if (await _roleManager.RoleExistsAsync(role))
            {
                if (!await _userManager.IsInRoleAsync(user, role))
                {
                    await _userManager.AddToRoleAsync(user, role);
                    assignedRoles.Add(role);
                }
            }
        }

        return new ApiResponse<List<string>>
        {
            IsSuccess = true,
            StatusCode = 200,
            Message = "The roles assigned successfully.",
            Response = assignedRoles
        };
    }
}