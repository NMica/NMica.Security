using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace KerberosUtil
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            var getTicketCommand = new Command("get-ticket")
            {
                new Option<string>(
                    "--kdc",
                    description: "Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work") {Required = true},
                new Option<string>(
                    "--user",
                    description: "Kerberos client principal. Ex. someuser@domain.com") {Required = true},
                new Option<string>(
                    "--password",
                    "Password for the client principal") {Required = true},
                new Option<string>(
                    "--spn",
                    "Destination service account or SPN. Ex http/myservice.domain.com") {Required = true}
            };
            getTicketCommand.Handler = CommandHandler.Create<string,string,string,string>(async(kdc, user, password, spn) =>
            {
                var split = user.Split("@");
                if (split.Length != 2)
                {
                    throw new Exception("User must be in <user>@<domain> format");
                }

                var domain = split[1];
                var config = Krb5Config.Default();
                var realmConfig = new Krb5RealmConfig();
                var kdcList = new List<string> {kdc};
                // realmConfig.GetType().GetProperty(nameof(realmConfig.Kdc)).SetValue(realmConfig, kdcList);
                // var realms = new Dictionary<string, Krb5RealmConfig>();
                // realms.Add(domain.ToUpper(), realmConfig);
                // config.GetType().GetProperty(nameof(config.Realms)).SetValue(config, realms);
                config.Realms[domain.ToUpper()].Kdc.Add(kdc);
                var client = new KerberosClient(config);
                
                
                var kerbCred = new KerberosPasswordCredential(user, password);
                await client.Authenticate(kerbCred);

                var ticket = await client.GetServiceTicket(spn);
                var ticket64 = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
                Console.WriteLine(ticket64);
                
            });
            
            var validateTicket = new Command("validate-ticket")
            {
                new Option<string>(
                    "--password",
                    description: "Principal password") {Required = true},
                new Option<string>(
                    "--domain",
                    description: "Domain name") { Required = true},
                new Option<string>(
                    "--user",
                    description: "Username if this is a User Account (case sensitive - without domain portion)"),
                new Option<string>(
                    "--computer",
                    description: "Computer name (without $) if this is a Computer Account  (case sensitive)"),
                new Option<string>(
                "--ticket",
                description: "Base64 ticket") { Required = true},
            };
            validateTicket.Handler = CommandHandler.Create<string,string,string,string,string>(async(password, domain, user, computer, ticket) =>
            {
                if(user == null && computer == null)
                    throw new Exception("User or computer must be supplied");
                
                var key = new KerberosKey(password, new PrincipalName(PrincipalNameType.NT_UNKNOWN, domain.ToUpper(), new[] {user ?? computer}), saltType: SaltType.ActiveDirectoryUser);
                var authenticator =  new KerberosAuthenticator(new KerberosValidator(key));
                var claims = await authenticator.Authenticate(ticket);
                Console.WriteLine($"Principal: {claims.Name}");
                Console.WriteLine($"Roles: {string.Join(',', claims.FindAll(claims.RoleClaimType).Select(x => x.Value))}");
            });
            
            var generateKey = new Command("generate-key")
            {
                new Option<bool>(
                    "--single-line",
                    description: "Generates PEM without any line breaks"),
            };
            generateKey.Handler = CommandHandler.Create<bool>((singleLine) =>
            {
                const int defaultPemLineLength = 67;
                var rsa = RSA.Create();
                var key64 = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                var sb = new StringBuilder();
                sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
                var wrapPattern = "(.{" + defaultPemLineLength + "})";
                sb.AppendLine(Regex.Replace(key64, wrapPattern, "$1\n", RegexOptions.Singleline));
                sb.Append("-----END RSA PRIVATE KEY-----");
                var pem = sb.ToString();
                if (singleLine)
                {
                    pem = Regex.Replace(pem, @"[\n\r]+", @"\n", RegexOptions.Singleline);
                }
                Console.WriteLine(pem);
            });

            
            
            var rootCommand = new RootCommand();
            rootCommand.AddCommand(getTicketCommand);
            rootCommand.AddCommand(validateTicket);
            rootCommand.AddCommand(generateKey);
            return await rootCommand.InvokeAsync(args);
            
        }
    }
}