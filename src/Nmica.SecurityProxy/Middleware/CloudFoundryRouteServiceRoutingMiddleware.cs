using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Service.Proxy;

namespace NMica.SecurityProxy.Middleware
{
    public class CloudFoundryRouteServiceRoutingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IHttpProxy _httpProxy;

        public CloudFoundryRouteServiceRoutingMiddleware(RequestDelegate next, IHttpProxy httpProxy)
        {
            _next = next;
            _httpProxy = httpProxy;
        }

        public async Task Invoke(HttpContext context)
        {
            var proxyFeature = context.GetReverseProxyFeature();
            var routeConfig = context.GetRouteConfig();
            var destinations = proxyFeature.AvailableDestinations;
            var clusterConfig = proxyFeature.ClusterSnapshot;
            string? destinationType = null;
            if(destinations.Count == 1 &&
               (destinations.First().Config.Options.Metadata?.TryGetValue("Type", out destinationType) ?? false) &&
               destinationType == "route-service" &&
               context.Request.Headers.TryGetValue("X-CF-Forwarded-Url", out var forwardUrl))
            {
                var transform = new DestinationSelectingTransformer(routeConfig.Transformer);
                await _httpProxy.ProxyAsync(context, forwardUrl, clusterConfig.HttpClient, new RequestProxyOptions(), transform);
                return;
            }

            await _next(context);
        }

        private class DestinationSelectingTransformer : HttpTransformer
        {
            private readonly HttpTransformer _original;

            public DestinationSelectingTransformer(HttpTransformer original)
            {
                _original = original;
            }

            public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
            {
                await _original.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);
                proxyRequest.RequestUri = new Uri(destinationPrefix);
            }
        }

    }
}
