using JWT_Token_Authentication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static Azure.Core.HttpHeader;
using System.Threading.Tasks;

namespace JWT_Token_Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly JWTSetting _jwtSettings;

        public AuthenticateController(ApplicationDbContext context, IOptions<JWTSetting> options)
        {
            _context = context;
            _jwtSettings = options.Value;
        }

        [HttpPost("GenerateToken")]
        public IActionResult Authenticate([FromBody] usercred user)
        {
            var _user = _context.Authentication_JWT.FirstOrDefault(o => o.Username == user.Username && o.Password == user.Password);
            if (_user == null)
                return Unauthorized();

            var token = GenerateToken(_user);
            return Ok(token);
        }

        private string GenerateToken(usercred user)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSettings.securitykey);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim("Username", user.Username),
                        new Claim(ClaimTypes.Role, user.Role)
                    }),
                    Expires = DateTime.UtcNow.AddMinutes(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to generate token.", ex);
            }
        }

        [HttpPost("RefreshToken")]
        public IActionResult RefreshToken(string refreshToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSettings.securitykey);

                // Validate and parse the existing refresh token
                var validatedToken = tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false
                }, out var securityToken);

                /*if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCultureIgnoreCase))
                {
                    throw new SecurityTokenException("Invalid refresh token");
                }*/

                var username = validatedToken.Claims.First(x => x.Type == "Username").Value;
                var role = validatedToken.Claims.First(x => x.Type == ClaimTypes.Role).Value;

                var newRefreshTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim("Username", username),
                        new Claim(ClaimTypes.Role, role)
                    }),
                    Expires = System.DateTime.Now.AddMinutes(11),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var newRefreshToken = tokenHandler.CreateToken(newRefreshTokenDescriptor);
                var newRefreshTokenString = tokenHandler.WriteToken(newRefreshToken);

               

                return Ok(newRefreshTokenString);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to generate refresh token.", ex);
            }
        }


    }
}
