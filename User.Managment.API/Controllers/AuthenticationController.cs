using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Managment.API.Models;
using User.Managment.API.Models.Authentication.SignUp;
using User.Managment.Service.Models;
using User.Managment.Service.Services;

namespace User.Managment.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailService emailService,
            ILogger<AuthenticationController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            //Check User Exist
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists" });

            //Add the User in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                
            };

            //var roleExist = await _roleManager.RoleExistsAsync("Admin");
            //if (!roleExist)
            //{
            //   var roleResult = await _roleManager.CreateAsync(new IdentityRole("Admin"));
            //}

            var existingRole =  await _roleManager.FindByNameAsync(role);

            if (existingRole != null )
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                     new Response { Status = "Error", Message = "User Failed to Create" });
                }

                //Add role the user here 
                await _userManager.AddToRoleAsync(user, role);
                return StatusCode(StatusCodes.Status200OK,
                     new Response { Status = "Success", Message = "User Created Successfully" });
            }

            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                     new Response { Status = "Error", Message = ("Role Does not Exist") });
            }
            //Assign a role .
        }

        [HttpGet]
        public IActionResult TestEmail()
        {
            try
            {
                var message = new Message(new string[]
                {"theideassolution@gmail.com"}, "Test", "<h1>Subscribe to my channel</h1>");

                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                     new Response { Status = "Success", Message = "Email Sent Successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occured during email sending in TestEmail.");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "An error occurred during email sending ." });
            }
        }
    }
}
