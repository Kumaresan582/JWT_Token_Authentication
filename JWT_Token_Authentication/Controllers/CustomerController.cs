using JWT_Token_Authentication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Token_Authentication.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class CustomerController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CustomerController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Roles = "admin")]
        [HttpGet("Getdata")]
        public IActionResult GetData()
        {
            var data = _context.DownloadTable.ToList();
            return Ok(data);
        }
    }
}