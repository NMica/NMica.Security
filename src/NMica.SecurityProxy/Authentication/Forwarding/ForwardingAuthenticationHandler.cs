using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NMica.SecurityProxy.Authentication.Forwarding
{
    public class ForwardingAuthenticationHandler : AuthenticationHandler<ForwardingAuthenticationOptions>
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;

        public ForwardingAuthenticationHandler([NotNull] [ItemNotNull] IOptionsMonitor<ForwardingAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock,
            IAuthenticationService authenticationService,
            IAuthenticationSchemeProvider authenticationSchemeProvider
            )
            : base(options,
            logger,
            encoder,
            clock)
        {
            _authenticationService = authenticationService;
            _authenticationSchemeProvider = authenticationSchemeProvider;
        }

        protected override string? ResolveTarget(string? scheme)
        {
            if (scheme == ForwardingAuthenticationDefaults.AuthenticationScheme || !Context.Request.Headers.TryGetValue("Authorization", out var authorizationHeaderValue))
            {
                return null;
            }
            var authorizationHeaderParts = authorizationHeaderValue.ToString().Split(" ");
            if (authorizationHeaderParts.Length <= 1)
            {
                return null;
            }

            scheme = authorizationHeaderParts[0];

            if (string.IsNullOrWhiteSpace(scheme) || !(Options.AuthenticationSchemes.Any() && Options.AuthenticationSchemes.Contains(scheme)))
            {
                return null;
            }
            return scheme;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }
        //
        // protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        // {
        //     if (!Context.Request.Headers.TryGetValue("Authorization", out var authorizationHeaderValue))
        //     {
        //         return AuthenticateResult.NoResult();
        //     }
        //
        //     var authorizationHeaderParts = authorizationHeaderValue.ToString().Split(" ");
        //     if (authorizationHeaderParts.Length != 2)
        //     {
        //         return AuthenticateResult.NoResult();
        //     }
        //     var scheme = authorizationHeaderParts[0];
        //     if (await _authenticationSchemeProvider.GetSchemeAsync(scheme) != null)
        //     {
        //         return await _authenticationService.AuthenticateAsync(Context, scheme);
        //     }
        //     return AuthenticateResult.NoResult();
        //
        // }
        //
        // protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        // {
        //     var defaultChallengeSchemeAsync = await _authenticationSchemeProvider.GetDefaultChallengeSchemeAsync();
        //     if (defaultChallengeSchemeAsync == null || defaultChallengeSchemeAsync.HandlerType == GetType())
        //     {
        //         Context.Response.StatusCode = 401;
        //         return;
        //     }
        //     await _authenticationService.ChallengeAsync(Context, defaultChallengeSchemeAsync.Name, properties);
        // }

    }
}
