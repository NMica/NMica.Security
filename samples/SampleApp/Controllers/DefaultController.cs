using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SampleApp.Controllers
{
    [ApiController]
    [Route("/")]
    public class DefaultController : Controller
    {
        private HttpContext _context;
        // GET
        public DefaultController(IHttpContextAccessor httpContextAccessor)
        {
            _context = httpContextAccessor.HttpContext;
        }

        public string Index()
        {
            string identity = "Anonymous";
            if (_context.Request.Headers.TryGetValue("X-CF-Identity", out var identityVal))
                identity = identityVal;
            var sb = new StringBuilder();
            sb.AppendLine($"Identity: {identity}");

            if (_context.Request.Headers.TryGetValue("X-CF-Roles", out var rolesVal))
            {
                sb.AppendLine("Roles:");
                foreach (var role in rolesVal.ToString().Split(","))
                {
                    sb.AppendLine($"- {role}");
                }
            }

            return sb.ToString();
        }

        [Authorize(policy: "jwt")]
        [Route("/jwt")]
        public object Jwt()
        {
            var identity = (ClaimsIdentity)_context.User.Identity;
            return identity.Claims.Select(x => new {x.Type, x.Value});
        }
    }
}