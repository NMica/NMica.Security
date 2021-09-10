using System.Net.Http.Headers;
using System.Threading.Tasks;
using IdentityServer4;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Transforms;

namespace NMica.SecurityProxy.Middleware.Transforms
{
    public class JwtPrincipalAppender : RequestTransform
    {
        private readonly IdentityServerTools _identityServerTools;
        private readonly IHttpContextAccessor _contextAccessor;

        public JwtPrincipalAppender(IdentityServerTools identityServerTools, IHttpContextAccessor contextAccessor)
        {
            _identityServerTools = identityServerTools;
            _contextAccessor = contextAccessor;
        }

        public override async ValueTask ApplyAsync(RequestTransformContext context)
        {
            if (context.HttpContext.User.Identity?.IsAuthenticated ?? false)
            {
                var jwt = await _identityServerTools.IssueJwtAsync(60, context.HttpContext.User.Claims);
                context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            }
        }

    }
}
