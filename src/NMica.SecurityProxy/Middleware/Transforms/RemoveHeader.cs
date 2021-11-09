using Yarp.ReverseProxy.Transforms;

namespace NMica.SecurityProxy.Middleware.Transforms;

public class RemoveHeader : RequestTransform
{
    private readonly string _headerName;

    public RemoveHeader(string headerName)
    {
        _headerName = headerName;
    }

    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        context.ProxyRequest.Headers.Remove(_headerName);
        return ValueTask.CompletedTask;
    }
}