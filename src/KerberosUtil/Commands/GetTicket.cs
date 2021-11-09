using System;
using System.CommandLine;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace KerberosUtil.Commands
{
    [UsedImplicitly]
    public class GetTicket : BaseCommand<GetTicket.Options>
    {
        [PublicAPI]
        public class Options 
        {
            [Description("Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work")]
            [Required]
            public string Kdc { get; set; } = null!;

            [Description("Kerberos client principal. Ex. someuser@domain.com")]
            [Required]
            public string User { get; set; } = null!;
            [Description("Password for the client principal")]
            [Required]
            public string Password { get; set; } = null!;
            [Description("Destination service account or SPN. Ex http/myservice.domain.com")]
            [Required]
            public string Spn { get; set; } = null!;
            [Description( "Instead of sending ticket to STDOUT, runs a local HTTP service which can be used to obtain tickets")]
            public bool StartServer { get; set; }

            public KerberosPasswordCredential NetworkCredential => CommandUtil.GetCredentials(User, Password);
        }

        public GetTicket(Options options) : base(options)
        {
        }

        public override async Task Run()
        {
            if (CommandOptions.StartServer)
            {
                await new WebHostBuilder()
                    .UseUrls("http://localhost:5022")
                    .UseKestrel()
                    .Configure(a => a.Run(async r => await r.Response.WriteAsync(await AcquireTicket())))
                    .Build()
                    .RunAsync();
            }
            else
            {
                Console.WriteLine(await AcquireTicket());
            }
        }

        async Task<string> AcquireTicket()
        {
            var credentials = CommandOptions.NetworkCredential;
            var config = Krb5Config.Default();
        
            config.Realms[credentials.Domain.ToUpper()].Kdc.Add(CommandOptions.Kdc);
            var client = new KerberosClient(config);
        
        
            var kerbCred = new KerberosPasswordCredential(CommandOptions.User, CommandOptions.Password);
            await client.Authenticate(kerbCred);
        
            var ticket = await client.GetServiceTicket(CommandOptions.Spn);
            var ticket64 = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
            return ticket64;
        }
    }
}