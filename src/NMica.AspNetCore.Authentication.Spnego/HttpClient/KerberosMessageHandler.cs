using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;

namespace NMica.AspNetCore.Authentication.Spnego
{
    [PublicAPI]
    public class KerberosMessageHandler : DelegatingHandler 
    {
        private readonly KerberosCredential _credential;
        private readonly KerberosClient _client;

        public KerberosMessageHandler(KerberosClient client, KerberosCredential credential)
        {
            _client = client;
            _credential = credential;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestUri = request.RequestUri ?? throw new InvalidOperationException("Request URI is not set");
            var spn = $"http/{requestUri.Host}"; 
            await _client.Authenticate(_credential);
            var ticket = await _client.GetServiceTicket(spn);
            var ticket64 = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
            request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", ticket64);
            return await base.SendAsync(request, cancellationToken);
        }
    }
}