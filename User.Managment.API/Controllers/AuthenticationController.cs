using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Managment.API.Models;
using User.Managment.API.Models.Authentication.Login;
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
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailService emailService,
            ILogger<AuthenticationController> logger,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _logger = logger;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            //Istifadecinin movcudlugunu yoxlayir
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists" });

            //Istifadecini yaradir ve databazaya elave edir
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,

            };


            //BU KOD ADMIN ROLU ASSIGN OLMADIGI UCUN YAZILMISDI
            //.NET CORE UN IDENTITYSI ILE ELAQELI BIR SEY IDI
            //-----------------------------------------------------------------------------------------
            ////var roleExist = await _roleManager.RoleExistsAsync("Admin");
            ////if (!roleExist)
            ////{
            ////   var roleResult = await _roleManager.CreateAsync(new IdentityRole("Admin"));
            ////}
            //------------------------------------------------------------------------------------------
            var existingRole = await _roleManager.FindByNameAsync(role);

            if (existingRole != null)
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
            //Istifadeciye rolu verir
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email Verified Successfully" });
            }
        return StatusCode(StatusCodes.Status500InternalServerError,
            new Response{Status = "Error" , Message = "This User does not exist"});
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user , loginModel.Password, false,true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);
            }
            if(user!=null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti , Guid.NewGuid().ToString()),
                };
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach(var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtToken = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
                //tokeni return edir

            }
            return Unauthorized();
        }
        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code ,string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name , user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti , Guid.NewGuid().ToString()),
                    };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach(var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GetToken(authClaims);
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });

                    //tokeni return edir
                }
            }

            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Fail", Message = $"Invalid Code" });
           
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires : DateTime.Now.AddDays(2),
                claims:authClaims,
                signingCredentials: new SigningCredentials(authSigningKey,SecurityAlgorithms.HmacSha256)
                );
            return token;
        }

    }
}
