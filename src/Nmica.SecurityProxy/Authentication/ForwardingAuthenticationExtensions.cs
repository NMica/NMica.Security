using System;
using Microsoft.AspNetCore.Authentication;

namespace NMica.SecurityProxy.Authentication
{
    public static class ForwardingAuthenticationExtensions
    {
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
}
