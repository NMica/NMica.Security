using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace NMica.SecurityProxy.Authentication.Forwarding;

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
}