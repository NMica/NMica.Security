using System.Collections.Generic;

namespace NMica.SecurityProxy.Middleware
{
    public class SimpleRouteProviderOptions
    {
        public List<string> Routes { get; set; } = new();
    }
}