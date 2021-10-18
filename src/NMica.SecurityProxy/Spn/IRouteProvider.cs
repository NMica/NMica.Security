using System.Collections.Generic;
using System.Threading.Tasks;

namespace NMica.SecurityProxy.Middleware
{
    public interface IRouteProvider
    {
        public Task<List<string>> GetRoutes();
    }
}