using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace NMica.SecurityProxy.Middleware
{
    public class SimpleRouteProvider : IRouteProvider
    {
        private readonly IOptionsMonitor<SimpleRouteProviderOptions> _options;

        public SimpleRouteProvider(IOptionsMonitor<SimpleRouteProviderOptions> options)
        {
            _options = options;
        }

        public Task<List<string>> GetRoutes() => Task.FromResult(_options.CurrentValue.Routes);
    }
}