using System.Security.Cryptography.X509Certificates;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NMica.AspNetCore.Authentication.Spnego;
using NMica.SecurityProxy.Authentication;
using NMica.SecurityProxy.Jwt;
using NMica.SecurityProxy.Middleware;
using NMica.SecurityProxy.Middleware.Transforms;
using Steeltoe.Security.Authentication.CloudFoundry;
using Steeltoe.Security.Authentication.Mtls;
using Yarp.ReverseProxy.Abstractions.Config;

namespace NMica.SecurityProxy
{
    [PublicAPI]
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            // Default configuration comes from AppSettings.json file in project/output
            Configuration = configuration;
            Environment = environment;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }

        // This method gets called by the runtime. Use this method to add capabilities to
        // the web application via services in the DI container.
        public void ConfigureServices(IServiceCollection services)
        {
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
                .AddCloudFoundryIdentityCertificate()
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
                    Configuration.GetSection("Spnego").Bind(options);
                });

            if (Environment.IsDevelopment())
            {
                // permit self signed mock pcf certs in local dev environments
                services.AddOptions<MutualTlsAuthenticationOptions>(CertificateAuthenticationDefaults.AuthenticationScheme)
                    .Configure(options =>
                    {
                        options.AllowedCertificateTypes = CertificateTypes.All;
                        options.RevocationMode = X509RevocationMode.NoCheck;
                    });
            }

            services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
                .Configure<IOptionsMonitor<JwtIssuingOptions>>((bearer, jwt) =>
                {
                    // allow accepting authorization tokens that were signed by us (as we're also issuer of said tokens)
                    bearer.TokenValidationParameters.IssuerSigningKey = jwt.CurrentValue.SigningKey;
                });

            services.AddAuthorization(opt => opt
                .AddPolicy("SameSpace", policy => policy
                    .SameSpace() // allow any app in current cf space to authenticate via mtls
                    .AddAuthenticationSchemes(CertificateAuthenticationDefaults.AuthenticationScheme)));


            services.AddCloudFoundryContainerIdentity(Configuration);
            services.AddSingleton<ITransformFactory, IdentityTransformFactory>();
            services.AddSingleton<KerberosTicketAppender>();
            services.AddSingleton<JwtPrincipalAppender>();
            // Add the reverse proxy to capability to the server
            services.AddReverseProxy()
                .LoadFromConfig(Configuration.GetSection("Proxy"))
                .AddTransforms(ctx => ctx.UseDefaultForwarders = false);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request
        // pipeline that handles requests
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseForwardedHeaders(new ForwardedHeadersOptions() { ForwardedHeaders = ForwardedHeaders.XForwardedProto });
            app.UseIdentityServer();
            app.UseCertificateForwarding();
            if (env.IsDevelopment())
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
        }
    }
}
