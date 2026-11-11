using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using yakovleva_pr8.Models;

namespace yakovleva_pr8.Controllers
{
    [ApiController]
    [Route("api/v1/tasks")]
    [Authorize]
    public class TasksController: ControllerBase
    {
        private readonly TrpoPr8Context _context;
        public TasksController(TrpoPr8Context context)
        {
            _context = context;
        }
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Models.Task>>> GetAllOwn()
        {
            var currentUser = User.Identity?.Name;

            var list = await _context.Tasks.Where(t => t.OwnerLogin == currentUser).ToListAsync();
            return Ok(list);
        }

        [HttpGet("{id:int}")]
        public async Task<ActionResult<Models.Task>> GetById(int id)
        {
            var task = await _context.Tasks.FindAsync(id);
            if (task == null)
                return NotFound();

            var currentUser = User.Identity?.Name;
            var isAdmin = User.IsInRole("Admin");
            if (!isAdmin && task.OwnerLogin != currentUser)
                return Forbid();

            return Ok(task);
        }

        public record TaskRequest(string Title, string Description);
        [HttpPost]
        public async Task<ActionResult<Models.Task>> CreateTask([FromBody] TaskRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest("Некорректно заполнены поля");

            if (string.IsNullOrWhiteSpace(request.Title) || string.IsNullOrWhiteSpace(request.Description))
                return BadRequest("Название и описание не должны быть пустыми");

            var currentUser = User.Identity?.Name;
            var task = new Models.Task
            {
                Title = request.Title,
                Description = request.Description,
                OwnerLogin = currentUser,
                IsCompleted = false
            };

            _context.Tasks.Add(task);
            await _context.SaveChangesAsync();
            return Created($"api/v1/tasks/{task.Id}", task);
        }
        public record PutTaskRequest(string Title, string Description, bool IsCompleted);
        [HttpPut("{id}")]
        public async Task<IActionResult> PutTask([FromRoute] int id, [FromBody] PutTaskRequest request)
        {
            var existingTask = await _context.Tasks.FindAsync(id);
            if (existingTask == null)
                return NotFound();

            var currentUser = User.Identity?.Name;
            var isAdmin = User.IsInRole("Admin");
            if (!isAdmin && existingTask.OwnerLogin != currentUser)
                return Forbid();

            if (string.IsNullOrWhiteSpace(request.Title) || string.IsNullOrWhiteSpace(request.Description))
                return BadRequest("Название и описание не должны быть пустыми");

            existingTask.Title = request.Title;
            existingTask.Description = request.Description;
            existingTask.IsCompleted = request.IsCompleted;

            await _context.SaveChangesAsync();
            return Ok(existingTask);
        }
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteTask([FromRoute] int id)
        {
            var existingTask = await _context.Tasks.FindAsync(id);
            if (existingTask == null)
                return NotFound();

            var currentUser = User.Identity?.Name;
            var isAdmin = User.IsInRole("Admin");
            if (!isAdmin && existingTask.OwnerLogin != currentUser)
                return Forbid();

            _context.Tasks.Remove(existingTask);
            await _context.SaveChangesAsync();

            return NoContent();
        }
        [HttpGet("all")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<IEnumerable<Models.Task>>> GetAll()
        {
            var list = await _context.Tasks.ToListAsync();
            return Ok(list);
        }
    }
}
