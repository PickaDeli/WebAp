using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebAp.Models;
using WebAp.Services;
using Microsoft.AspNetCore.Authorization;


namespace WebAp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService service)
        {
            _userService = service;
        }
        // GET: api/User
        /// <summary>
        /// Gets the information of all users in database
        /// </summary>
        /// <returns>List of</returns>

        [HttpGet]
        [Authorize]
        public async Task<ActionResult<IEnumerable<UserDTO>>> GetUsers()
        {
            return Ok(await _userService.GetUsersAsync());
        }
        // GET: api/User/5
        /// <summary>
        /// Gets a user using username
        /// </summary>
        /// <param name="username"></param>
        /// <returns>User information for one user</returns>

        [HttpGet("{userName}")]
        public async Task<ActionResult<UserDTO>> GetUser(string username)
        {
            UserDTO? user = await _userService.GetUserAsync(username);

            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        // PUT: api/User/5
        /// <summary>
        /// Updates user's username
        /// </summary>
        /// <param name="username"></param>
        /// <param name="user"></param>
        /// <returns>Updated useraname</returns>
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{username}")]
        public async Task<IActionResult> PutUser(string username, User user)
        {
            if (username != user.UserName)
            {
                return BadRequest();
            }
            if (await _userService.UpdateUserASync(user))
            {
                return NoContent();
            }
            return NotFound();
        }

        // POST: api/User
        /// <summary>
        /// Add new user
        /// </summary>
        /// <param name="user"></param>
        /// <returns>New user</returns>
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<UserDTO?>> PostUser(User user)
        {
            UserDTO? newUser = await _userService.NewUserAsync(user);

            if (newUser == null)
            {
                return Problem("Username not available.", statusCode: 400);
            }
            return CreatedAtAction("Getuser", new { username = user.UserName }, user);
        }

        // DELETE: api/User/5
        /// <summary>
        /// Deletes user
        /// </summary>
        /// <param name="username"></param>
        /// <returns>If user is found, deletes user from database</returns>
        [HttpDelete("{username}")]
        public async Task<IActionResult> DeleteUser(string username)
        {
            if (await _userService.DeleteUserAsync(username))
            {
                return Ok();
            }

            return Problem("Username not found");
        }
    }
}