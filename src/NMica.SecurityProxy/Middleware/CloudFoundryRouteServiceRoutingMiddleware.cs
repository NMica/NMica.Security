﻿using Yarp.ReverseProxy.Forwarder;

namespace NMica.SecurityProxy.Middleware;

public class CloudFoundryRouteServiceRoutingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IHttpForwarder _httpProxy;

    public CloudFoundryRouteServiceRoutingMiddleware(RequestDelegate next, IHttpForwarder httpProxy)
    {
        _next = next;
        _httpProxy = httpProxy;
    }

    public async Task Invoke(HttpContext context)
    {
        var proxyFeature = context.GetReverseProxyFeature();
        var routeConfig = context.GetRouteModel();
        var destinations = proxyFeature.AvailableDestinations;
        var clusterConfig = proxyFeature.Cluster;
        string? destinationType = null;
        if(destinations.Count == 1 && (destinations[0].Model.Config.Metadata?.TryGetValue("Type", out destinationType) ?? false) && destinationType == "route-service")
        {
            if (!context.Request.Headers.TryGetValue("X-CF-Forwarded-Url", out var forwardUrl))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Destination is a Cloud Foundry route service, but X-CF-Forwarded-Url is not included");
                return;
            }
            var transform = new DestinationSelectingTransformer(routeConfig.Transformer);
            await _httpProxy.SendAsync(context, forwardUrl, clusterConfig.HttpClient, new ForwarderRequestConfig(), transform);
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