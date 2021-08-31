using System;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Kerberos.NET.Credentials;
using Microsoft.Extensions.Options;
using NMica.AspNetCore.Authentication.Spnego;
using Yarp.ReverseProxy.Service.RuntimeModel.Transforms;

namespace NMica.SecurityProxy.Middleware.Transforms
{
    public class KerberosTicketAppender : RequestTransform
    {
        private readonly IOptionsMonitor<SpnegoAuthenticationOptions> _options;

        public KerberosTicketAppender(IOptionsMonitor<SpnegoAuthenticationOptions> options)
        {
            _options = options;
        }

        public override async ValueTask ApplyAsync(RequestTransformContext context)
        {
            var options = _options.Get(SpnegoAuthenticationDefaults.AuthenticationScheme);
            var client = options.KerberosClient;
            if (client == null)
            {
                throw new InvalidOperationException("Kerberos client isn't configured");
            }
            var credential = options.Credentials!;
            var kerbCredential = new KerberosPasswordCredential(credential.UserName, credential.Password, credential.Domain);
            await client.Authenticate(kerbCredential);
            var destinationHost = new Uri(context.DestinationPrefix);
            var spn = $"http/{destinationHost.Host}";
            var ticket = await client.GetServiceTicket(spn);
            var base64Ticket = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
            context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", base64Ticket);
        }
    }
}
