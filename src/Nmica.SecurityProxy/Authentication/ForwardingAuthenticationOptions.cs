using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;

namespace NMica.SecurityProxy.Authentication
{
    public class ForwardingAuthenticationOptions : AuthenticationSchemeOptions
    {
        public List<string> AuthenticationSchemes { get; set; } = new();
    }
}
