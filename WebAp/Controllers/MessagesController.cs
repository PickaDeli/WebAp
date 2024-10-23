using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAp.Models;
using WebAp.Services;


namespace WebAp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MessagesController : ControllerBase
    {
        private readonly IMessageService _messageService;
        private readonly IUserAuthenticationService _userAuthenticationService;

        public MessagesController(IMessageService service, IUserAuthenticationService userAuthenticationService)
        {
            _messageService = service;
            _userAuthenticationService = userAuthenticationService;
        }
        // GET: api/Messages
        /// <summary>
        /// Gets all messages
        /// </summary>
        /// <returns>All messages</returns>
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Message>>> GetMessages()
        {
            return Ok(await _messageService.GetMessagesAsync());
        }

        // GET: api/Messages/5
        /// <summary>
        /// Gets one message by id
        /// </summary>
        /// <param name="id"></param>
        /// <returns>A message that corresponds to id</returns>
        [HttpGet("{id}")]

        public async Task<ActionResult<MessageDTO>> GetMessage(long id)
        {
            //var message = await _messageService.Messages.FindAsync(id);
            MessageDTO? message = await _messageService.GetMessageAsync(id);
            if (message == null)
            {
                return NotFound();
            }

            return message;
        }

        // PUT: api/Messages/5
        /// <summary>
        /// Modify existing message using id
        /// </summary>
        /// <param name="id"></param>
        /// <param name="message"></param>
        /// <returns>Updated message</returns>
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutMessage(long id, MessageDTO message)
        {
            if (id != message.Id)
            {
                return BadRequest();
            }

            bool result = await _messageService.UpdateMessageAsync(message);

            if (result)
            {
                return NotFound();
            }

            return NoContent();
        }

        // POST: api/Messages
        /// <summary>
        /// Posts new message
        /// </summary>
        /// <param name="message"></param>
        /// <returns>New message</returns>
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<MessageDTO>> PostMessage(MessageDTO message)
        {
            MessageDTO? newMessage = await _messageService.NewMessageAsync(message);

            if (newMessage == null)
            {
                return Problem();
            }

            return CreatedAtAction("Get Message", new { id = message.Id, message });
        }

        // DELETE: api/Messages/5
        /// <summary>
        /// Deletes message using id.
        /// </summary>
        /// <param name="id"></param>
        /// <returns>If succeeded, deletes message corresponding to id</returns>
        [HttpDelete("{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteMessage(long id)
        {
            string username = this.User.FindFirst(ClaimTypes.Name).Value;
            if (!await _userAuthenticationService.isMyMessage(username, id))
            {
                return BadRequest();
            }
            bool result = await _messageService.DeleteMessageAsync(id);
            //var message = await _context.Messages.FindAsync(id);
            if (!result)
            {
                return NotFound();
            }

            return NoContent();
        }


    }
}
