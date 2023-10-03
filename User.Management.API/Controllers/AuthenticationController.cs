using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
using User.Management.Services.Models;
using User.Management.Services.Models.Authentication.SignUp;
using User.Management.Services.Models.Authentication.Login;
using User.Management.Services.Services;
using User.Management.Services.Models.Authentication.Token;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly SignInManager<IdentityUser> _signInManager;

        public IConfiguration _configuration { get; set; }
        public IUserManagement _userManagement { get; }
        public TokenManagement _tokenManager { get; }

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService, IConfiguration configuration,
            SignInManager<IdentityUser> signInManager,
            IUserManagement userManagement,
            TokenManagement tokenManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
            _userManagement = userManagement;
            _tokenManager = tokenManager;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterUser registerUser)
        {
            var tokenResponse = await _userManagement.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess)
            {
                await _userManagement.AssignRoleRoUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email, IsSuccess = true }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "User created successfully.", IsSuccess = true });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Failed", Message = tokenResponse.Message, IsSuccess = false });
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email verified successfully.", IsSuccess = true });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User does not exist." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _userManagement.GetOtpByLoginAsync(loginModel);
            if (loginOtpResponse.Response == null)
            {
                return Unauthorized();
            }
            else
            {
                var tokenResponse = await _tokenManager.AuthenticateUserAsync(loginOtpResponse.Response, loginModel);

                return Ok(new
                {
                    token = tokenResponse.Response.Token,
                    expiration = tokenResponse.Response.Expiration
                });
            }
        }

        [HttpPost("login-2FA")]
        public async Task<IActionResult> LoginWithOtp(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);

            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);

            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var tokenResponse = await _tokenManager.CreateTokenAndReport(user);

                    return Ok(new
                    {
                        token = tokenResponse.Response.Token,
                        expiration = tokenResponse.Response.Expiration
                    });
                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "Invalid code. " });
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email }, "Forgot password link", forgotPasswordLink);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password change email message sent  to {user.Email}.Please check your mailbox . ", IsSuccess = true });

            }
            return StatusCode(StatusCodes.Status404NotFound,
                   new Response { Status = "Failed.", Message = "Email not found" });
        }

        [HttpGet("reset-password")]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!resetPassResult.Succeeded)
                {
                    foreach (var Error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(Error.Code, Error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password has been successfully changed.", IsSuccess = true });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Failed.", Message = "Could not send mail to email.Please try again later." });



        }
    }
}
