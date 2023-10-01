using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.Login;
public class LoginModel
{
    [Required(ErrorMessage ="Username is required.")]
    public string Username { get; set; } = null!;
    
    [Required(ErrorMessage ="Password is required.")]
    public string Password { get; set; } = null!;

}