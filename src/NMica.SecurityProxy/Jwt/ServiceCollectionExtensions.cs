using System.Linq;
using System.Security.Cryptography;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace NMica.SecurityProxy.Jwt
{
    public static class ServiceCollectionExtensions
    {
        public static IIdentityServerBuilder AddJwtIssuing(this IServiceCollection services)
        {
            services.AddOptions<JwtIssuingOptions>()
                .Configure<IConfiguration>((opt, config) =>
                {
                    var pem = config.GetValue<string>("Jwt:SigningKey");
                    if (!PemEncoding.TryFind(pem, out var pemFields))
                    {
                        return;
                    }

                    var label = pem[pemFields.Label];
                    if (label.StartsWith("RSA"))
                    {
                        var rsa = RSA.Create();
                        rsa.ImportFromPem(pem);
                        opt.SigningKey = new RsaSecurityKey(rsa);
                    }
                })
                .Validate(opt => opt.SigningKey != null, "Signing key is not set");
            services.AddSingleton<ISigningCredentialStore, SigningKeyCredentialsProvider>();
            services.AddSingleton<IValidationKeysStore, SigningKeyCredentialsProvider>();


            // services.AddIdentityServer()
            var builder = services.AddIdentityServerBuilder()
                .AddRequiredPlatformServices()
                // .AddCookieAuthentication()
                .AddCoreServices()
                .AddDefaultEndpoints()
                .AddPluggableServices()
                .AddValidators()
                .AddResponseGenerators()
                .AddDefaultSecretParsers()
                .AddDefaultSecretValidators()
                .AddInMemoryPersistedGrants()
                .AddInMemoryClients(Enumerable.Empty<Client>())
                .AddInMemoryIdentityResources(Enumerable.Empty<IdentityResource>())
                .AddInMemoryCaching()
                .AddInMemoryApiResources(Enumerable.Empty<ApiResource>())
                .AddInMemoryApiScopes(Enumerable.Empty<ApiScope>())


                ;
            services.Configure<IdentityServerOptions>(opt =>
                {
                    opt.Endpoints = new EndpointsOptions()
                    {
                        EnableAuthorizeEndpoint = false,
                        EnableIntrospectionEndpoint = false,
                        EnableTokenEndpoint = false,
                        EnableCheckSessionEndpoint = false,
                        EnableDeviceAuthorizationEndpoint = false,
                        EnableEndSessionEndpoint = false,
                        EnableJwtRequestUri = false,
                        EnableTokenRevocationEndpoint = false,
                        EnableUserInfoEndpoint = false
                    };
                    opt.Discovery = new DiscoveryOptions()
                    {
                        ShowClaims = false,
                        ShowApiScopes = false,
                        ShowGrantTypes = false,
                        ShowIdentityScopes = false,
                        ShowResponseModes = false,
                        ShowResponseTypes = false,
                        ShowExtensionGrantTypes = false,
                        ShowTokenEndpointAuthenticationMethods = false
                    };
                });

            return builder;
        }
    }
}
