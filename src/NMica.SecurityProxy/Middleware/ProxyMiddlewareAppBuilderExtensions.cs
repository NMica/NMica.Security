using Microsoft.AspNetCore.Builder;
using Yarp.ReverseProxy.Middleware;

namespace NMica.SecurityProxy.Middleware
{
    public static class ProxyMiddlewareAppBuilderExtensions
    {
        public static IApplicationBuilder UseCloudFoundryRouteServiceRouting(this IReverseProxyApplicationBuilder proxy)
        {
            return proxy.UseMiddleware<CloudFoundryRouteServiceRoutingMiddleware>();
        }
    }
}
