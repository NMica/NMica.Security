using Microsoft.AspNetCore.Authentication;

namespace NMica.SecurityProxy.Authentication.Forwarding;

public class ForwardingAuthenticationOptions : AuthenticationSchemeOptions
{
    public List<string> AuthenticationSchemes { get; set; } = new();
}