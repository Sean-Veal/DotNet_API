using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using DatingApp.API.Data;
using DatingApp.API.DTOs;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers {
    [AllowAnonymous]
    [Route ("api/[controller]")]
    [ApiController]
    public class AuthController : Controller {
        // private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AuthController (IConfiguration config, 
        IMapper mapper, 
        UserManager<User> userManager,
        SignInManager<User> signInManager) {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
            _mapper = mapper;
        }

        [HttpPost ("register")]
        public async Task<IActionResult> Register ([FromBody] UserRegisterDTO user) {
            // validate request if not using ApiController
            // if(!ModelState.IsValid) return BadRequest(ModelState);

            // user.Username = user.Username.ToLower ();

            // if (await _repo.UserExists (user.Username)) {
            //     return BadRequest ("Username is already taken");
            // }

            var userToCreate = _mapper.Map<User> (user);

            var result = await _userManager.CreateAsync(userToCreate, user.Password);

            var userToReturn = _mapper.Map<UserForDetailedDTO> (userToCreate);

            if (result.Succeeded)
            {

                return CreatedAtRoute ("GetUser",
                    new { controller = "Users", id = userToReturn.Id },
                    userToReturn);
            }

            return BadRequest(result.Errors);
        }

        [HttpPost ("login")]
        public async Task<IActionResult> Login (UserLoginDTO userLoginDto) {
            var user = await _userManager.FindByNameAsync(userLoginDto.Username);

            var result = await _signInManager.CheckPasswordSignInAsync(user, userLoginDto.Password, false);

            if (result.Succeeded)
            {
                var appUser = await _userManager.Users.Include(p => p.Photos)
                    .FirstOrDefaultAsync(u => u.NormalizedUserName == userLoginDto.Username.ToUpper());

                var userToReturn = _mapper.Map<UserForListDTO> (appUser);

                return Ok (new {
                    token = GenerateJwtToken (appUser),
                    user = userToReturn
                });
            }

            return Unauthorized();

        }

        private async Task<string> GenerateJwtToken (User user) {
            var claims = new List<Claim> {
                new Claim (ClaimTypes.NameIdentifier, user.Id.ToString ()),
                new Claim (ClaimTypes.Name, user.UserName)
            };

            var roles = await _userManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey (Encoding.UTF8.GetBytes (_config.GetSection ("AppSettings:Token").Value));

            var creds = new SigningCredentials (key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity (claims),
                Expires = DateTime.Now.AddDays (1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler ();

            var token = tokenHandler.CreateToken (tokenDescriptor);

            return tokenHandler.WriteToken (token);
        }
    }
}