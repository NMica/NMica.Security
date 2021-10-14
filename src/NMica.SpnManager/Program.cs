using System.DirectoryServices.Protocols;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using NMica.AspNetCore.Authentication.Spnego;
using NMica.AspNetCore.Authentication.Spnego.Ldap;
using NMica.SpnManager;
using NMica.SpnManager.Controllers;
using Steeltoe.Extensions.Configuration.Placeholder;


var builder = WebApplication.CreateBuilder(args);
builder.Configuration.Dispose();
builder.Configuration
    .AddYamlFile("appsettings.yaml")
    .AddYamlFile($"appsettings.{builder.Environment.EnvironmentName}.yaml")
    .AddEnvironmentVariables()
    .AddCommandLine(args)
    .AddPlaceholderResolver();

// Add services to the container.
var services = builder.Services;

services.AddControllers();
services.AddSwaggerGen(c => { c.SwaggerDoc("v1", new() { Title = "NMica.SpnManager", Version = "v1" }); });
services.AddAuthentication(SpnegoAuthenticationDefaults.AuthenticationScheme)
    .AddSpnego(options => builder.Configuration.GetSection("Spnego").Bind(options));

services.AddScoped<LdapConnection>(ctx =>
{
    var options = ctx.GetRequiredService<IOptionsSnapshot<LdapOptions>>().Get(SpnegoAuthenticationDefaults.AuthenticationScheme);
    var di = new LdapDirectoryIdentifier(server: options.Host, options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
    var connection = new LdapConnection(di, options.Credentials);
    connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
    connection.SessionOptions.ProtocolVersion = 3; //Setting LDAP Protocol to latest version
    connection.Timeout = TimeSpan.FromMinutes(1);
    connection.AutoBind = true;
    // connection.SessionOptions.SecureSocketLayer = options.UseSsl;
    if (!options.ValidateServerCertificate)
    {
        connection.SessionOptions.VerifyServerCertificate = (ldapConnection, certificate) => true;
    }

    connection.Bind();
    return connection;
});

services.AddOptions<SpnManagementOptions>().BindConfiguration("SpnManagement");

services.AddAuthorization(opt =>
{
    opt.AddPolicy(KnownPolicies.ViewSpn, policy => policy
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(SpnegoAuthenticationDefaults.AuthenticationScheme));
    opt.AddPolicy(KnownPolicies.EditSpn, policy => policy
        .RequireRole(builder.Configuration.GetValue<string>("SpnCreatorGroup") ?? "SpnCreators")
        .AddAuthenticationSchemes(SpnegoAuthenticationDefaults.AuthenticationScheme));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "NMica.SpnManager v1"));
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();