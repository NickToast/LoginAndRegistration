//User controller
//User models & login models
//User views folders & views
//Routes home, register, login, logout
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LoginAndRegistration.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;
using System.ComponentModel.DataAnnotations;

namespace LoginAndRegistration.Controllers;


public class UserController : Controller
{
    private readonly ILogger<UserController> _logger;

    private MyContext db;

    public UserController(ILogger<UserController> logger, MyContext context)
    {
        _logger = logger;
        db = context;
    }

    [HttpGet("")]
    public IActionResult Index()
    {
        return View();
    }

    //REGISTRATION FIRST TO TEST DATABASE
    [HttpPost("/register")]
    public IActionResult Register(User newUser)
    {
        if(!ModelState.IsValid)
        {
            return View("Index");
        }

        PasswordHasher<User> hashBrowns = new PasswordHasher<User>();

        newUser.Password = hashBrowns.HashPassword(newUser, newUser.Password);

        db.Users.Add(newUser);
        db.SaveChanges();
        //Set a new session to a variable with the newUser information
        //Key and Value pair, UUID key name and the new user's UserId as the value
        HttpContext.Session.SetInt32("UUID", newUser.UserId);

        return RedirectToAction("Success");
    }

    //LOGIN ROUTES
    [HttpPost("/login")]
    public IActionResult Login(LoginUser userSubmission) //parameter to pass in, the user submission of their email and password
    {
        //EMAIL CHECK
        //Check if submission is valid according to our model
        if (!ModelState.IsValid) //If submission is not valid according to our model
        {
            return View("Index"); //return them back to the index view to register/login again
        }

        //Check if email submitted is in our database
        User? userInDb = db.Users.FirstOrDefault(e => e.Email == userSubmission.LoginEmail);

        //If nothing comes back, add an error and return the same view to render the validation
        if (userInDb == null)
        {
            ModelState.AddModelError("LoginEmail", "Invalid Email Address/Password");
            return View("Index");
        }

        //PASSWORD CHECK
        //Invoke password hasher
        PasswordHasher<LoginUser> hashbrowns = new PasswordHasher<LoginUser>();
        //LoginUser, hashed password, password submitted by user
        var result = hashbrowns.VerifyHashedPassword(userSubmission, userInDb.Password, userSubmission.LoginPassword);
        

        if (result == 0)
        {
            ModelState.AddModelError("LoginEmail", "Invalid Email Address/Password"); //string key, error message parameters
            return View("Index");
        }

        //PASSES ALL CHECKS, HANDLE SUCCESS NOW
        //We want to set the session key:value pair to id:UserId and we'll use this to keep track if our user is logged in
        HttpContext.Session.SetInt32("UUID", userInDb.UserId);
        return RedirectToAction("Success");
    }

    [HttpGet("success")]
    [SessionCheck]
    public IActionResult Success()
    {

        return View();
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }


    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    // Name this anything you want with the word "Attribute" at the end
    public class SessionCheckAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            // Find the session, but remember it may be null so we need int?
            int? userId = context.HttpContext.Session.GetInt32("UUID");
            // Check to see if we got back null
            if(userId == null)
            {
                // Redirect to the Index page if there was nothing in session
                // "Home" here is referring to "HomeController", you can use any controller that is appropriate here
                context.Result = new RedirectToActionResult("Index", "User", null);
            }
        }
    }

    public class UniqueEmailAttribute : ValidationAttribute
    {
        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            // Though we have Required as a validation, sometimes we make it here anyways
            // In which case we must first verify the value is not null before we proceed
            if(value == null)
            {
                // If it was, return the required error
                return new ValidationResult("Email is required!");
            }
        
            // This will connect us to our database since we are not in our Controller
            MyContext _context = (MyContext)validationContext.GetService(typeof(MyContext));
            // Check to see if there are any records of this email in our database
            if(_context.Users.Any(e => e.Email == value.ToString()))
            {
                // If yes, throw an error
                return new ValidationResult("Email must be unique!");
            } else {
                // If no, proceed
                return ValidationResult.Success;
            }
        }
    }
}
