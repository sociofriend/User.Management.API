using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace User.Management.API.Controllers;
[Authorize(Roles = "HR")]
[Route("api/[controller]")]
[ApiController]
public class AdminController : ControllerBase
{
    [HttpGet("Employees")]
    public IEnumerable<string> Get()
    {
        return new List<string> {"name1", "name2"};
    }
} 