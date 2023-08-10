#pragma warning disable CS8618
//using statements and namespace go here
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

[NotMapped]
public class LoginUser
{
    //No other fields!
    [Required(ErrorMessage = "Email is required to login")]
    [EmailAddress]
    public string LoginEmail { get; set; }

    [Required]
    public string LoginPassword { get; set; }
}