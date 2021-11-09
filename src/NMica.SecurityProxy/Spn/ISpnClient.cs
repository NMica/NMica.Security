namespace NMica.SecurityProxy.Spn;

public interface ISpnClient
{
    Task<List<string>> GetAllSpn(CancellationToken cancellationToken = default);
    Task<bool> AddSpn(string spn);
    Task<bool> DeleteSpn(string spn);
}