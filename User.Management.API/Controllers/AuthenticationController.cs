using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.Login;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Services.Models;
using User.Management.Services.Services;

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

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService, IConfiguration configuration,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterUser registerUser, string role)
        {
            //check user exists
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User Already exists!." });
            }
            //if user does not exist, add user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = bool.Parse(_configuration["UserSettings:TwoFactorEnabled"]!)
            };

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password); //bring changes to DB and will save changes
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "User not created." });
                }

                // await _userManager.AddToRoleAsync(user, role);

                await _userManager.AddToRoleAsync(user, role); //DB, save changes. UserRoles table

                //add token to verify the email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"User created succesfully.Confirmation email sent to {user.Email}." });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Role does not exist." });
            }
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
                        new Response { Status = "Success", Message = "Email verified successfully." });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User does not exist." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            //checking the user
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = $"We have sent an OTP to your email {user.Email}" });
            }

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
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

                //how to add the token to DB?
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken), //string
                    expiration = jwtToken.ValidTo
                });
            }

            return Unauthorized();
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

                    //how to add the token to DB?
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken), //string
                        expiration = jwtToken.ValidTo
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
                    new Response { Status = "Success", Message = $"Password change email message sent  to {user.Email}.Please check your mailbox . " });

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
                    new Response { Status = "Success", Message = $"Password has been successfully changed." });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Failed.", Message = "Could not send mail to email.Please try again later." });



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
}
