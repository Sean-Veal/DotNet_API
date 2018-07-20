using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.DTOs;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthRepository _repo;
        public AuthController(IAuthRepository repo)
        {
            _repo = repo;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UserRegisterDTO user)
        {
            user.Username = user.Username.ToLower();

            if(await _repo.UserExists(user.Username)) {
                return BadRequest("Username is already taken");
            }

            var userToCreate = new User
            {
                Username = user.Username
            };

            var createdUser = await _repo.Register(userToCreate, user.Password);

            return StatusCode(201);
        }
    }
}