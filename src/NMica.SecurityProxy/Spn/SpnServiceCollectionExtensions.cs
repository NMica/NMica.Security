using Kerberos.NET.Credentials;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using NMica.AspNetCore.Authentication.Spnego;
using NMica.AspNetCore.Authentication.Spnego.HttpClient;
using Steeltoe.Common;

namespace NMica.SecurityProxy.Spn;

public static class SpnServiceCollectionExtensions
{
    public static IServiceCollection AddSpnManagement(this IServiceCollection services)
    {
        services.TryAddSingleton(ctx => ctx
            .GetRequiredService<IOptionsMonitor<SpnegoAuthenticationOptions>>()
            .Get(SpnegoAuthenticationDefaults.AuthenticationScheme).KerberosClient!);
        services.TryAddSingleton<KerberosCredential>(ctx =>
        {
            var networkCredential = ctx.GetRequiredService<IOptionsMonitor<SpnegoAuthenticationOptions>>().Get(SpnegoAuthenticationDefaults.AuthenticationScheme).Credentials;
            return new KerberosPasswordCredential(networkCredential.UserName, networkCredential.Password, networkCredential.Domain);
        });
        if (Platform.IsCloudFoundry)
        {
            services.TryAddSingleton<IRouteProvider, CloudFoundryRouteProvider>();
        }
        else
        {
            services.AddOptions<SimpleRouteProviderOptions>().BindConfiguration("SpnManagement");
            services.TryAddSingleton<IRouteProvider, SimpleRouteProvider>();
        }
        services.AddOptions<SpnManagerOptions>()
            .BindConfiguration("SpnManagement")
            .PostConfigure(opt =>
            {
                opt.Enabled ??= opt.ServiceUrl != null;
                opt.ServiceUrl ??= "https://localhost:7167";
            })
            .Validate(options => !(options.Enabled.HasValue && options.Enabled.Value && options.ServiceUrl == null), "Spn Management is enabled but management service URL is not set");
        services.AddTransient<KerberosMessageHandler>();
        services.AddHttpClient<ISpnClient, SpnClient>((ctx, client) =>
            {
                var options = ctx.GetRequiredService<IOptionsMonitor<SpnManagerOptions>>().CurrentValue;
                client.BaseAddress = new Uri(options.ServiceUrl!);
            })
            .AddHttpMessageHandler<KerberosMessageHandler>();
        services.AddHostedService<SpnManagerHostedService>();
        return services;
    }
}