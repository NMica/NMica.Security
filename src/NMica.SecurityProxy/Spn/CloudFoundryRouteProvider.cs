using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace NMica.SecurityProxy.Middleware
{
    public class CloudFoundryRouteProvider : IRouteProvider
    {
        private readonly IConfiguration _configuration;

        public CloudFoundryRouteProvider(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public Task<List<string>> GetRoutes()
        {
            var appInfo = new Steeltoe.Common.ApplicationInstanceInfo(_configuration);
            return Task.FromResult(appInfo.Uris.ToList());
        }
    }
}