using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using User.Management.Services.Models;
using User.Management.Services.Models.Authentication.User;
using User.Management.Services.Models.Authentication.Login;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using User.Management.Services.Models.Authentication.Token;
using System.Text;


namespace User.Management.Services.Services;

public class TokenManagement
{
    public UserManager<IdentityUser> _userManager { get; }
    public IEmailService _emailService;
    private readonly IConfiguration _configuration;

    public TokenManagement(UserManager<IdentityUser> userManager,
                            IEmailService mailService,
                            IConfiguration configuration)
    {
        _userManager = userManager;
        _emailService = mailService;
        _configuration = configuration;
    }


    public async Task<ApiResponse<CreateTokenResponse>> AuthenticateUserAsync(
        LoginOtpResponse loginOtpResponse, LoginModel loginMode)
    {
        var user = loginOtpResponse.User;
        //check if 2FA is enabled
        if (loginOtpResponse.IsTwoFactorEnabled)
        {
            return SendOtpEmail(user, loginOtpResponse.Token);
        }
        else
        {
            return await SendAuthLink(user, loginMode);
        }
    }

    private ApiResponse<CreateTokenResponse> SendOtpEmail(IdentityUser user, string token)
    {
        var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
        _emailService.SendEmail(message);

        return new ApiResponse<CreateTokenResponse>
        {
            IsSuccess = true,
            Message = "OPT code sent to user.",
            StatusCode = 200,
            Response = new CreateTokenResponse()
            {
                Token = token,
                User = user
            }
        };
    }

    private async Task<ApiResponse<CreateTokenResponse>> SendAuthLink(IdentityUser user, LoginModel loginModel)
    {
        var passwordMatches = await _userManager.CheckPasswordAsync(user, loginModel.Password);

        if (passwordMatches)
        {
            return await CreateTokenAndReport(user);
        }
        else
        {
            return new ApiResponse<CreateTokenResponse>
            {
                IsSuccess = true,
                Message = "Password does not match.",
                StatusCode = 200,
            };
        }
    }

    public async Task<ApiResponse<CreateTokenResponse>> CreateTokenAndReport(IdentityUser user)
    {
        //create claim list
        var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

        //add roles to the client 
        var userRoles = await _userManager.GetRolesAsync(user);
        foreach (var role in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }
        //generate the token with the claims
        var jwtToken = GetToken(authClaims); //object

        return new ApiResponse<CreateTokenResponse>
        {
            IsSuccess = true,
            Message = "Confirmation email sent to user.",
            StatusCode = 200,
            Response = new CreateTokenResponse()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                User = user,
                Expiration = jwtToken.ValidTo
            }
        };
    }

    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8
                .GetBytes(_configuration["JWT:Secret"]!));
        var token = new JwtSecurityToken(
            audience: _configuration["JWT:ValidAudience"],
            issuer: _configuration["JWT:ValidIssuer"],
            expires: DateTime.UtcNow.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return token;
    }
}
