using Microsoft.AspNetCore.Authentication;

namespace NMica.SecurityProxy.Authentication.Forwarding;

public static class ForwardingAuthenticationExtensions
{
    /// <summary>
    /// Selects authentication scheme based on the name of Authorization header
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddForwarding(
        this AuthenticationBuilder builder,
        Action<ForwardingAuthenticationOptions>? configureOptions)
    {
        return builder.AddForwarding(ForwardingAuthenticationDefaults.AuthenticationScheme, configureOptions);
    }

    public static AuthenticationBuilder AddForwarding(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<ForwardingAuthenticationOptions>? configureOptions)
    {
        builder.AddScheme<ForwardingAuthenticationOptions, ForwardingAuthenticationHandler>(authenticationScheme, configureOptions);
        return builder;
    }
}