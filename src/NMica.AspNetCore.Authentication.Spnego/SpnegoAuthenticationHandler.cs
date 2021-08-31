using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using AuthenticationOptions = Kerberos.NET.Client.AuthenticationOptions;

namespace NMica.AspNetCore.Authentication.Spnego
{
    public class SpnegoAuthenticationHandler : AuthenticationHandler<SpnegoAuthenticationOptions>
    {
        private readonly ILoggerFactory _loggerFactory;

        public SpnegoAuthenticationHandler(
            IOptionsMonitor<SpnegoAuthenticationOptions> optionsMonitor,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock
            ) : base(optionsMonitor, loggerFactory, encoder, clock)
        {
            _loggerFactory = loggerFactory;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            
            if (!AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var authorizationHeader) ||
                !SpnegoAuthenticationDefaults.AuthenticationScheme.Equals(authorizationHeader.Scheme, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrEmpty(authorizationHeader.Parameter))
            {
                Logger.LogTrace("Credentials not supplied as part of Authorization Header");
                return AuthenticateResult.NoResult();
            }

            var base64Token = authorizationHeader.Parameter;

            try
            {
                Logger.LogTrace("Validating incoming SPNEGO Ticket \n{Ticket}", base64Token);
                // var principalName = new PrincipalName(PrincipalNameType.NT_UNKNOWN, Options.Credentials!.Domain.ToUpper(), new[] {Options.Credentials.UserName});
                // var key = new KerberosKey(Options.Credentials.Password, principalName, saltType: SaltType.ActiveDirectoryUser);
                // var authenticator = new KerberosAuthenticator(new KerberosValidator(key));
                var credentials = new KerberosPasswordCredential(Options.Credentials.UserName,
                    Options.Credentials.Password, Options.Credentials.Domain);
                if (Options.KerberosClient?.Configuration != null)
                    credentials.Configuration = Options.KerberosClient.Configuration;
                var authenticator = new KerberosAuthenticator(new ActiveDirectoryKerberosValidator(credentials));
                var identity = await authenticator.Authenticate(base64Token);
                ClaimsPrincipal principal;
                
                if (Options.LdapRolesClaimsTransformer != null)
                {
                    principal = await Options.LdapRolesClaimsTransformer.TransformAsync(new ClaimsPrincipal(identity));
                }
                else
                {
                    principal = new ClaimsPrincipal(identity);
                }

                var ticket = new AuthenticationTicket(
                    principal,
                    new AuthenticationProperties(),
                    SpnegoAuthenticationDefaults.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);


            }
            catch (SecurityException e)
            {
                if (e.Message.Contains("CRC", StringComparison.OrdinalIgnoreCase))
                {
                    return AuthenticateResult.Fail(new KerberosValidationException("Provided credentials don't match ticket", e));
                }

                return AuthenticateResult.Fail(e);
            }
            catch (NotSupportedException e) when (e.Message.Contains("NTLM", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.Fail(e.Message);
            }
            catch (Exception e)
            {
                return AuthenticateResult.Fail(e.ToString());
            }
        }

        
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {

            Response.StatusCode = 401;
            Response.Headers.Append(HeaderNames.WWWAuthenticate, $"Negotiate");
            return Task.CompletedTask;
        }

        protected override Task InitializeHandlerAsync()
        {
            return Task.CompletedTask;
        }
    }
}
