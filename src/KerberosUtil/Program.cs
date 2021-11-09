using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Binding;
using System.CommandLine.Builder;
using System.CommandLine.Hosting;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Reflection;
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
using KerberosUtil;
using KerberosUtil.Commands;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using NMica.AspNetCore.Authentication.Spnego;

var commandTypes =  AppDomain.CurrentDomain.GetAssemblies()
    .SelectMany(x => x.GetTypes())
    .Where(x => x.BaseType is { IsGenericType: true } && x.BaseType.GetGenericTypeDefinition().IsAssignableTo(typeof(BaseCommand<>)))
    .Select(x => (commandType: x, optionsType: x.BaseType!.GetGenericArguments()[0]))
    .ToList();

var commands = commandTypes
    .Select(commandAndOptions =>
    {
        var (commandType, optionsType) = commandAndOptions;
        // var command = CommandUtil.FromOptions(optionsType, commandType.Name.ToArgName());
        var command = new Command(commandType.Name.ToArgName());
        foreach (var property in optionsType.GetProperties().Where(x => x.CanWrite))
        {
            var optionName = $"--{property.Name.ToArgName()}";
            var isRequired = property.GetCustomAttribute<RequiredAttribute>() != null;
            var description = property.GetCustomAttribute<DescriptionAttribute>()?.Description;
            var option = new Option(optionName, description, property.PropertyType)
            {
                IsRequired = isRequired
            };
            command.AddOption(option);
        }
        var invoker = new Invoker(commandType);
        var invokerRunMethod = invoker.GetType()!.GetMethod(nameof(Invoker.Run))!.MakeGenericMethod(optionsType);
        command.Handler = CommandHandler.Create(invokerRunMethod, invoker);
        return command;
    })
    .ToList();

var builder = new CommandLineBuilder();
foreach (var command in commands)
{
    builder.AddCommand(command);
}

builder.AddGlobalOption(new Option("--prompt", "Prompt for missing required values", typeof(bool)));

builder.UseHost(_ => Host.CreateDefaultBuilder(), host =>
    {
        host.ConfigureHostConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string>()
        {
            {"Logging:LogLevel:Microsoft.Hosting.Lifetime", "Error"}
        }));
        host.ConfigureLogging(c => c.AddConsole());
    })
    .UsePrompt()
    .UseDefaults()
    .Build()
    .InvokeAsync(args);

class Invoker
{
    public Invoker(Type commandType)
    {
        _commandType = commandType;
    }

    private readonly Type _commandType;
    public async Task Run<TOptions>(TOptions options, IHost host)
    {
        var command = (BaseCommand<TOptions>)ActivatorUtilities.CreateInstance(host.Services, _commandType, options! );
        await command.Run();
    }
}
//
// namespace KerberosUtil
// {
//     class Program
//     {
//         static async Task<int> Main(string[] args)
//         {
//             await BuildCommandLine()
//                 .UseHost(_ => Host.CreateDefaultBuilder(), host =>
//                 {
//                     host.ConfigureHostConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string>()
//                     {
//                         {"Logging:LogLevel:Microsoft.Hosting.Lifetime", "Error"}
//                     }));
//                     host.ConfigureLogging(c => c.AddConsole());
//                 })
//                 .UsePrompt()
//                 .UseDefaults()
//                 .Build()
//                 .InvokeAsync(args);
//             return 0;
//         }
//
//
//         private static CommandLineBuilder BuildCommandLine()
//         {
//             var builder = new CommandLineBuilder();
//             var commands = GetAllCommandTypes()
//                 .Select(x =>
//                 {
//                     var (commandType, optionsType) = x;
//                     var command = CommandUtil.FromOptions(optionsType, commandType.Name.ToArgName());
//                     var invoker = new Invoker(commandType);
//                     var invokerRunMethod = invoker.GetType()!.GetMethod(nameof(Invoker.Run))!.MakeGenericMethod(optionsType);
//                     command.Handler = CommandHandler.Create(invokerRunMethod, invoker);
//                     return command;
//                 })
//                 .ToList();
//             foreach (var command in commands)
//             {
//                 builder.AddCommand(command);
//             }
//
//             builder.AddGlobalOption(new Option("--prompt", "Prompt for missing required values", typeof(bool)));
//             return builder;
//         }
//         private static IEnumerable<(Type commandType, Type optionsType)> GetAllCommandTypes() => AppDomain.CurrentDomain.GetAssemblies()
//             .SelectMany(x => x.GetTypes())
//             .Where(x => x.BaseType is { IsGenericType: true } && x.BaseType.GetGenericTypeDefinition().IsAssignableTo(typeof(BaseCommand<>)))
//             .Select(x => (x, x.BaseType!.GetGenericArguments()[0]));
//         
//         class Invoker
//         {
//             public Invoker(Type commandType)
//             {
//                 _commandType = commandType;
//             }
//
//             private Type _commandType;
//             public async Task Run<TOptions>(TOptions options, IHost host)
//             {
//                 var command = (BaseCommand<TOptions>)ActivatorUtilities.CreateInstance(host.Services, _commandType, options! );
//                 // var command = (BaseCommand<TOptions>)host.Services.GetRequiredService(_commandType);
//                 await command.Run();
//             }
//         }
//
//         static async Task<int> Main2(string[] args)
//         {
//             var getTicketCommand = new Command("get-ticket")
//             {
//                 new Option<string>(
//                     "--kdc",
//                     description: "Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work") {IsRequired = true},
//                 new Option<string>(
//                     "--user",
//                     description: "Kerberos client principal. Ex. someuser@domain.com") {IsRequired = true},
//                 new Option<string>(
//                     "--password",
//                     "Password for the client principal") { IsRequired = true},
//                 new Option<string>(
//                     "--spn",
//                     "Destination service account or SPN. Ex http/myservice.domain.com") {IsRequired = true},
//                 new Option<bool>(
//                     "--start-server", 
//                     "Instead of sending ticket to STDOUT, runs a local HTTP service which can be used to obtain tickets")
//             };
//             getTicketCommand.Handler = CommandHandler.Create<string,string,string,string,bool>(async(kdc, user, password, spn, startServer) =>
//             {
//                 async Task<string> GetTicket()
//                 {
//                     var credentials = GetCredentials(user, password);
//                     var config = Krb5Config.Default();
//         
//                     config.Realms[credentials.Domain.ToUpper()].Kdc.Add(kdc);
//                     var client = new KerberosClient(config);
//         
//         
//                     var kerbCred = new KerberosPasswordCredential(user, password);
//                     await client.Authenticate(kerbCred);
//         
//                     var ticket = await client.GetServiceTicket(spn);
//                     var ticket64 = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
//                     return ticket64;
//                 }
//         
//                 if (startServer)
//                 {
//                     await new WebHostBuilder()
//                         .UseUrls("http://localhost:5022")
//                         .UseKestrel()
//                         .Configure(a => a.Run(async r => await r.Response.WriteAsync(await GetTicket())))
//                         .Build()
//                         .RunAsync();
//                 }
//                 else
//                 {
//                     Console.WriteLine(await GetTicket());
//                 }
//             });
//             
//             var validateTicket = new Command("validate-ticket")
//             {
//                 new Option<string>(
//                     "--password",
//                     description: "Principal password") {IsRequired = true},
//                 new Option<string>(
//                     "--domain",
//                     description: "Domain name") { IsRequired = true},
//                 new Option<string>(
//                     "--user",
//                     description: "Username if this is a User Account (case sensitive - without domain portion)"),
//                 new Option<string>(
//                     "--computer",
//                     description: "Computer name (without $) if this is a Computer Account  (case sensitive)"),
//                 new Option<string>(
//                     "--kdc",
//                     description: "Location of KDC which is used to fetch principal salts. If not supplied, decryption will be attempted via convention based salts."),
//                 new Option<string>(
//                 "--ticket",
//                 description: "Base64 ticket") { IsRequired = true},
//             };
//             validateTicket.Handler = CommandHandler.Create<string,string,string,string,string, string>(async(password, domain, user, computer, kdc, ticket) =>
//             {
//                 if(user == null && computer == null)
//                     throw new Exception("User or computer must be supplied");
//                 //
//                 // var key = new KerberosKey(password, new PrincipalName(PrincipalNameType.NT_UNKNOWN, domain.ToUpper(), new[] {user ?? computer}), saltType: SaltType.ActiveDirectoryUser);
//                 // var authenticator =  new KerberosAuthenticator(new KerberosValidator(key));
//                 var credentials = new KerberosPasswordCredential(user, password, domain);
//                 credentials.Configuration = Krb5Config.Default();
//                 credentials.Configuration.Realms[domain.ToUpper()].Kdc.Add(kdc);
//                 var authenticator = new KerberosAuthenticator(new ActiveDirectoryKerberosValidator(credentials));
//                 
//                 var claims = await authenticator.Authenticate(ticket);
//                 Console.WriteLine($"Principal: {claims.Name}");
//                 Console.WriteLine($"Roles: {string.Join(',', claims.FindAll(claims.RoleClaimType).Select(x => x.Value))}");
//             });
//             
//             var generateKey = new Command("generate-key")
//             {
//                 new Option<bool>(
//                     "--single-line",
//                     description: "Generates PEM without any line breaks"),
//             };
//             generateKey.Handler = CommandHandler.Create<bool>((singleLine) =>
//             {
//                 const int defaultPemLineLength = 67;
//                 var rsa = RSA.Create();
//                 var key64 = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
//                 var sb = new StringBuilder();
//                 sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
//                 var wrapPattern = "(.{" + defaultPemLineLength + "})";
//                 sb.AppendLine(Regex.Replace(key64, wrapPattern, "$1\n", RegexOptions.Singleline));
//                 sb.Append("-----END RSA PRIVATE KEY-----");
//                 var pem = sb.ToString();
//                 if (singleLine)
//                 {
//                     pem = Regex.Replace(pem, @"[\n\r]+", @"\n", RegexOptions.Singleline);
//                 }
//                 Console.WriteLine(pem);
//             });
//         
//             var getSaltCommand = new Command("get-salt")
//             {
//                 new Option<string>(
//                     "--kdc",
//                     description: "Key Destribution Center (KDC). Try AD domain name if you don't know this value - will usually work") {IsRequired = true},
//                 new Option<string>(
//                     "--user",
//                     description: "Kerberos client principal. Ex. someuser@domain.com") {IsRequired = true},
//             };
//             getSaltCommand.Handler = CommandHandler.Create<string, string>(async (kdc, user) =>
//             {
//                 var credentials = GetCredentials(user, "not-used");
//                 var credential = new KerberosPasswordCredential(user, "not-used", credentials.Domain);
//                 var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);
//                 var asReq = asReqMessage.EncodeApplication();
//         
//                 var config = Krb5Config.Default();
//                 config.Realms[credentials.Domain.ToUpper()].Kdc.Add(kdc);
//             
//                 var transport = new KerberosTransportSelector(
//                     new IKerberosTransport[]
//                     {
//                         new TcpKerberosTransport(null),
//                         new UdpKerberosTransport(null),
//                         new HttpsKerberosTransport(null)
//                     },
//                     config,
//                     null
//                 )
//                 {
//                     ConnectTimeout = TimeSpan.FromSeconds(3)
//                 };
//                 try
//                 {
//                     await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);
//                 }
//                 catch (KerberosProtocolException pex)
//                 {
//                     var salt = pex?.Error?.DecodePreAuthentication()?
//                         .Where(p => p.Type == PaDataType.PA_ETYPE_INFO2)
//                         .SelectMany(x => x.DecodeETypeInfo2())
//                         .Select(x => x.Salt)
//                         .FirstOrDefault();
//                     Console.WriteLine(salt);
//                 }
//             });
//         
//             
//             
//             var rootCommand = new RootCommand();
//             rootCommand.AddCommand(getTicketCommand);
//             rootCommand.AddCommand(validateTicket);
//             rootCommand.AddCommand(generateKey);
//             rootCommand.AddCommand(getSaltCommand);
//             return await rootCommand.InvokeAsync(args);
//             
//         }
//         
//         private static NetworkCredential GetCredentials(string username, string password)
//         {
//             var split = username.Split("@");
//             if (split.Length != 2)
//             {
//                 throw new Exception("User must be in <user>@<domain> format");
//             }
//         
//             return new NetworkCredential(split[0], password, split[1]);
//         }
//     }
// }