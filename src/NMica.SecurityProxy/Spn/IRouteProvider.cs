namespace NMica.SecurityProxy.Spn;

public interface IRouteProvider
{
    public Task<List<string>> GetRoutes();
}