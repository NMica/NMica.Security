using Microsoft.Extensions.Options;

namespace NMica.SecurityProxy.Spn
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