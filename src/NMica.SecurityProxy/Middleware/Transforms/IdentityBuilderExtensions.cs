using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms.Builder;

namespace NMica.SecurityProxy.Middleware.Transforms
{
    public static class TransformBuilderExtensions
    {
        public static TransformBuilderContext AppendJwtPrincipal(this TransformBuilderContext context)
        {
            var transformer = context.Services.GetRequiredService<JwtPrincipalAppender>();
            context.RequestTransforms.Add(transformer);
            return context;
        }

        public static TransformBuilderContext RemoveHeader(this TransformBuilderContext context, string header)
        {
            var transformer = new RemoveHeader(header);
            context.RequestTransforms.Add(transformer);
            return context;
        }


    }
}
