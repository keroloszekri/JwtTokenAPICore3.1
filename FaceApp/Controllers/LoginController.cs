using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FaceApp.Model;
using Microsoft.AspNetCore.Antiforgery.Internal;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace FaceApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }


        public IActionResult Login ( string userName , string password)
        {
            UserModel login = new UserModel();
            login.UserName = userName;
            login.Password = password;
            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);
            if(user != null)
            {
                var TokenString = GenerateJsonWebToken(user);
                response = Ok(new { token = TokenString });

            }

            return response;
        }

        private string GenerateJsonWebToken(UserModel userInfo)
        {
            var SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var Credential = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);

            var Cliams = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub , userInfo.UserName),
                new Claim(JwtRegisteredClaimNames.Email , userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti , Guid.NewGuid().ToString()),
            };

            var Token = new JwtSecurityToken
            (
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                Cliams,
                expires: DateTime.Now.AddDays(365),
                signingCredentials: Credential
            );

            var encodeToken = new JwtSecurityTokenHandler().WriteToken(Token);
            return encodeToken;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;
            if(login.UserName=="K" && login.Password =="123")
            {
                user = new UserModel
                {
                    UserName = "K",
                    Password = "123",
                    Email = "K@gmsil.com"
                };
            }

            return user; 
        }


        [Authorize]
        [HttpPost("Post")]
        public string Post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();
            var userName = claim[0].Value;
            return "welome to : " + userName;       
        }

        // If it return not found use these 2 line
        //[Authorize(AuthenticationSchemes = "Bearer")]
        //[HttpGet]

        // [Authorize]
        [HttpGet("Get")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "Value1", "Value2" , "Value3" };
        }
    }
}