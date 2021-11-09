using System.CommandLine;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Net;
using JetBrains.Annotations;
using Kerberos.NET;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using NMica.AspNetCore.Authentication.Spnego;

namespace KerberosUtil.Commands
{
    [UsedImplicitly]
    public class ValidateTicket : BaseCommand<ValidateTicket.Options>
    {
        [PublicAPI]
        public class Options 
        {
            [Description("Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work")]
            [Required]
            public string Kdc { get; set; } = null!;

            [Description(@"The account which is the receiver of the ticket (the service). Format: user@domain.com or $ComputerName\domain.com")]
            [Required]
            public string Principal { get; set; } = null!;
        
            [Description("Principal password")]
            [Required]
            public string Password { get; set; } = null!;

            [Description("Base64 ticket")] 
            [Required]
            public string Ticket { get; set; } = null!;

        }
        
        public ValidateTicket(Options options) : base(options)
        {
        }

        public override async Task Run()
        {
            var credentials = CommandUtil.GetCredentials(CommandOptions.Principal, CommandOptions.Password);
            credentials.Configuration = Krb5Config.Default();
            credentials.Configuration.Realms[credentials.Domain.ToUpper()].Kdc.Add(CommandOptions.Kdc);
            var authenticator = new KerberosAuthenticator(new ActiveDirectoryKerberosValidator(credentials));
                
            var claims = await authenticator.Authenticate(CommandOptions.Ticket);
            Console.WriteLine($"Principal: {claims.Name}");
            Console.WriteLine($"Roles:");
            foreach (var role in claims.FindAll(claims.RoleClaimType).Select(x => x.Value))
            {
                Console.WriteLine($"  {role}");
            }
        }
    }
}