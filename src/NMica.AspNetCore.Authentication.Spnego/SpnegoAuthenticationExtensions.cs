using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using NMica.AspNetCore.Authentication.Spnego.Configuration;
using NMica.AspNetCore.Authentication.Spnego.Ldap;

namespace NMica.AspNetCore.Authentication.Spnego
{
    [PublicAPI]
    public static class SpnegoAuthenticationExtensions
    {
        public static AuthenticationBuilder AddSpnego(
            this AuthenticationBuilder builder,
            Action<SpnegoAuthenticationOptions>? configureOptions)
        {
            return builder.AddSpnego(SpnegoAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddSpnego(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<SpnegoAuthenticationOptions>? configureOptions)
        {
            builder.Services.AddSingleton(svc => ActivatorUtilities.CreateInstance<LdapRolesClaimsTransformer>(svc, authenticationScheme));
            builder.Services.AddSingleton<IStartupFilter>(services => services
                .GetRequiredService<IEnumerable<LdapRolesClaimsTransformer>>()
                .First(x => x.Name == authenticationScheme));
            builder.AddScheme<SpnegoAuthenticationOptions, SpnegoAuthenticationHandler>(authenticationScheme, configureOptions);
            builder.Services.AddOptions<SpnegoAuthenticationOptions>(authenticationScheme)
                .PostConfigure<IServiceProvider>((opt, services) =>
                {
                    if (string.IsNullOrEmpty(opt.Ldap.UsersQuery))
                    {
                        opt.Ldap.UsersQuery = opt.Ldap.GroupsQuery;
                    }

                    if (opt.Ldap.Port == 0)
                    {
                        opt.Ldap.Port = opt.Ldap.UseSsl ? 636 : 389;
                    }

                    opt.LdapRolesClaimsTransformer = services.GetRequiredService<IEnumerable<LdapRolesClaimsTransformer>>()
                        .FirstOrDefault(x => x.Name == authenticationScheme);
                });
            // make ldap named options come from SpnegoOptions.Ldap options
            builder.Services.AddSingleton<IOptionsChangeTokenSource<LdapOptions>>(svc =>
            {
                var linkedOptions = svc.GetRequiredService<IOptionsMonitor<SpnegoAuthenticationOptions>>();
                return new LinkedOptionsChangeTrackingSource<LdapOptions,SpnegoAuthenticationOptions>(authenticationScheme, linkedOptions);
            });
            builder.Services.AddSingleton<IOptionsFactory<LdapOptions>, LdapOptionsFactory>();
            builder.Services.AddOptions<LdapOptions>(authenticationScheme);

            return builder;
        }
        private class LdapOptionsFactory : IOptionsFactory<LdapOptions>
        {
            private readonly IOptionsMonitor<SpnegoAuthenticationOptions> _options;

            public LdapOptionsFactory(IOptionsMonitor<SpnegoAuthenticationOptions> options) => _options = options;

            public LdapOptions Create(string name) => _options.Get(name).Ldap;
        }
    }
}
