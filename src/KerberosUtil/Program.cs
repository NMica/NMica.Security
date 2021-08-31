using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Linq;
using System.Net;
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
using Kerberos.NET.Transport;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using NMica.AspNetCore.Authentication.Spnego;

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
                    "Destination service account or SPN. Ex http/myservice.domain.com") {Required = true},
                new Option<bool>(
                    "--start-server", 
                    "Instead of sending ticket to STDOUT, runs a local HTTP service which can be used to obtain tickets")
            };
            getTicketCommand.Handler = CommandHandler.Create<string,string,string,string,bool>(async(kdc, user, password, spn, startServer) =>
            {
                async Task<string> GetTicket()
                {
                    var credentials = GetCredentials(user, password);
                    var config = Krb5Config.Default();

                    config.Realms[credentials.Domain.ToUpper()].Kdc.Add(kdc);
                    var client = new KerberosClient(config);


                    var kerbCred = new KerberosPasswordCredential(user, password);
                    await client.Authenticate(kerbCred);

                    var ticket = await client.GetServiceTicket(spn);
                    var ticket64 = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
                    return ticket64;
                }

                if (startServer)
                {
                    await new WebHostBuilder()
                        .UseUrls("http://localhost:5022")
                        .UseKestrel()
                        .Configure(a => a.Run(async r => await r.Response.WriteAsync(await GetTicket())))
                        .Build()
                        .RunAsync();
                }
                else
                {
                    Console.WriteLine(await GetTicket());
                }
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
                    "--kdc",
                    description: "Location of KDC which is used to fetch principal salts. If not supplied, decryption will be attempted via convention based salts."),
                new Option<string>(
                "--ticket",
                description: "Base64 ticket") { Required = true},
            };
            validateTicket.Handler = CommandHandler.Create<string,string,string,string,string, string>(async(password, domain, user, computer, kdc, ticket) =>
            {
                if(user == null && computer == null)
                    throw new Exception("User or computer must be supplied");
                //
                // var key = new KerberosKey(password, new PrincipalName(PrincipalNameType.NT_UNKNOWN, domain.ToUpper(), new[] {user ?? computer}), saltType: SaltType.ActiveDirectoryUser);
                // var authenticator =  new KerberosAuthenticator(new KerberosValidator(key));
                var credentials = new KerberosPasswordCredential(user, password, domain);
                credentials.Configuration = Krb5Config.Default();
                credentials.Configuration.Realms[domain.ToUpper()].Kdc.Add(kdc);
                var authenticator = new KerberosAuthenticator(new ActiveDirectoryKerberosValidator(credentials));
                
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

            var getSaltCommand = new Command("get-salt")
            {
                new Option<string>(
                    "--kdc",
                    description: "Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work") {Required = true},
                new Option<string>(
                    "--user",
                    description: "Kerberos client principal. Ex. someuser@domain.com") {Required = true},
            };
            getSaltCommand.Handler = CommandHandler.Create<string, string>(async (kdc, user) =>
            {
                var credentials = GetCredentials(user, "not-used");
                var credential = new KerberosPasswordCredential(user, "not-used", credentials.Domain);
                var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);
                var asReq = asReqMessage.EncodeApplication();

                var config = Krb5Config.Default();
                config.Realms[credentials.Domain.ToUpper()].Kdc.Add(kdc);
            
                var transport = new KerberosTransportSelector(
                    new IKerberosTransport[]
                    {
                        new TcpKerberosTransport(null),
                        new UdpKerberosTransport(null),
                        new HttpsKerberosTransport(null)
                    },
                    config,
                    null
                )
                {
                    ConnectTimeout = TimeSpan.FromSeconds(3)
                };
                try
                {
                    await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);
                }
                catch (KerberosProtocolException pex)
                {
                    var salt = pex?.Error?.DecodePreAuthentication()?
                        .Where(p => p.Type == PaDataType.PA_ETYPE_INFO2)
                        .SelectMany(x => x.DecodeETypeInfo2())
                        .Select(x => x.Salt)
                        .FirstOrDefault();
                    Console.WriteLine(salt);
                }
            });

            
            
            var rootCommand = new RootCommand();
            rootCommand.AddCommand(getTicketCommand);
            rootCommand.AddCommand(validateTicket);
            rootCommand.AddCommand(generateKey);
            rootCommand.AddCommand(getSaltCommand);
            return await rootCommand.InvokeAsync(args);
            
        }

        private static NetworkCredential GetCredentials(string username, string password)
        {
            var split = username.Split("@");
            if (split.Length != 2)
            {
                throw new Exception("User must be in <user>@<domain> format");
            }

            var domain = split[1];
            return new NetworkCredential(split[0], password, split[1]);
        }
        
        private static async Task<string> GetSaltFromKdc(string kdc, string username, string password, string domain)
        {
            var credential = new KerberosPasswordCredential(username, password, domain);
            var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);
            var asReq = asReqMessage.EncodeApplication();

            var config = Krb5Config.Default();
            config.Realms[domain.ToUpper()].Kdc.Add(kdc);
            
            var transport = new KerberosTransportSelector(
                new IKerberosTransport[]
                {
                    new TcpKerberosTransport(null),
                    new UdpKerberosTransport(null),
                    new HttpsKerberosTransport(null)
                },
                config,
                null
            )
            {
                ConnectTimeout = TimeSpan.FromSeconds(3)
            };
            try
            {
                await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);
            }
            catch (KerberosProtocolException pex)
            {
                var salt = pex?.Error?.DecodePreAuthentication()?
                    .Where(p => p.Type == PaDataType.PA_ETYPE_INFO2)
                    .SelectMany(x => x.DecodeETypeInfo2())
                    .Select(x => x.Salt)
                    .FirstOrDefault();
                return salt;
            }
            
            return null;
        }
    }
}