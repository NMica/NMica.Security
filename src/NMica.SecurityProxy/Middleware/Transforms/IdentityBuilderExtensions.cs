using Yarp.ReverseProxy.Transforms.Builder;

namespace NMica.SecurityProxy.Middleware.Transforms;

public static class TransformBuilderExtensions
{
    public static TransformBuilderContext AppendJwtPrincipal(this TransformBuilderContext context)
    {
        var transformer = ActivatorUtilities.CreateInstance<JwtPrincipalAppender>(context.Services);
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