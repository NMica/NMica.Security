using System.Security.Cryptography.X509Certificates;
using AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NMica.AspNetCore.Authentication.Spnego;
using NMica.SecurityProxy.Authentication.Forwarding;
using NMica.SecurityProxy.Jwt;
using NMica.SecurityProxy.Middleware;
using NMica.SecurityProxy.Middleware.Transforms;
using NMica.SecurityProxy.Spn;
using Steeltoe.Extensions.Configuration.Placeholder;
using Steeltoe.Security.Authentication.CloudFoundry;
using Steeltoe.Security.Authentication.Mtls;


var builder = WebApplication.CreateBuilder(args);
builder.Configuration.Dispose();
builder.Configuration
    .AddJsonFile("appsettings.json")
    .AddYamlFile("appsettings.yaml")
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json")
    .AddYamlFile($"appsettings.{builder.Environment.EnvironmentName}.yaml")
    .AddEnvironmentVariables()
    .AddCommandLine(args)
    .AddPlaceholderResolver();

var config = builder.Configuration;
var environment = builder.Environment;

var services = builder.Services;
services.AddJwtIssuing();
services.AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = ForwardingAuthenticationDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = SpnegoAuthenticationDefaults.AuthenticationScheme;
    })
    .AddForwarding(options =>
    {
        options.AuthenticationSchemes.Add(SpnegoAuthenticationDefaults.AuthenticationScheme);
        options.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
    })
    // .AddCloudFoundryIdentityCertificate()
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            RequireAudience = false,
            ValidateAudience = false,
            ValidateActor = false,
            ValidateIssuer = false,
        };
    })
    .AddSpnego(options =>
    {
        config.GetSection("Spnego").Bind(options);
    });
    // .AddApiKey("X-API-KEY", config.GetValue<string>("ApiKey"));

services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptionsMonitor<JwtIssuingOptions>>((bearer, jwt) =>
    {
        // allow accepting authorization tokens that were signed by us (as we're also issuer of said tokens)
        bearer.TokenValidationParameters.IssuerSigningKey = jwt.CurrentValue.SigningKey;
    });

services.AddCloudFoundryCertificateAuth();

if (environment.IsDevelopment())
{
    // permit self signed mock pcf certs in local dev environments
    services.AddOptions<MutualTlsAuthenticationOptions>(CertificateAuthenticationDefaults.AuthenticationScheme)
        .Configure(options =>
        {
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.RevocationMode = X509RevocationMode.NoCheck;
        });
}

// services.AddAuthorization(opt => opt
//     .AddPolicy("SameSpace", policy => policy
//         .SameSpace() // allow any app in current cf space to authenticate via mtls
//         .AddAuthenticationSchemes(CertificateAuthenticationDefaults.AuthenticationScheme)));

services.AddAuthorization(opt => opt
    .AddPolicy("ValidApiKey", policy => policy
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(ApiKeyDefaults.AuthenticationScheme)));

// add extra transforms 
// services.AddSingleton<KerberosTicketAppender>();
// services.AddSingleton<JwtPrincipalAppender>();
// Add the reverse proxy to capability to the server
services.AddReverseProxy()
    .LoadFromConfig(config.GetSection("Proxy"))
    .AddTransformFactory<IdentityTransformFactory>()
    .AddTransforms(ctx => ctx.UseDefaultForwarders = false);

services.AddSpnManagement();

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedProto });
app.UseIdentityServer();
app.UseCertificateForwarding();
if (environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
app.UseAuthentication();
app.UseRouting();
app.UseAuthorization();
// Register the reverse proxy routes
app.UseEndpoints(endpoints =>
{
    endpoints.MapReverseProxy(proxy =>
    {
        // proxy.UseSessionAffinity();
        // proxy.UseLoadBalancing();
        // proxy.UsePassiveHealthChecks();
        proxy.UseCloudFoundryRouteServiceRouting();
    });
});

app.Run();