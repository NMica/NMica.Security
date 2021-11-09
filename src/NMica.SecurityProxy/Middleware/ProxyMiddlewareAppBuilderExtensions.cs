namespace NMica.SecurityProxy.Middleware;

public static class ProxyMiddlewareAppBuilderExtensions
{
    /// <summary>
    /// Use cluster dynamic destination selection based on Cloud Foundry X-CF-Forwarded-Url header 
    /// </summary>
    /// <param name="proxy"></param>
    /// <returns></returns>
    public static IApplicationBuilder UseCloudFoundryRouteServiceRouting(this IReverseProxyApplicationBuilder proxy)
    {
        return proxy.UseMiddleware<CloudFoundryRouteServiceRoutingMiddleware>();
    }
}