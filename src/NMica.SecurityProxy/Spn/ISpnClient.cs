using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NMica.SecurityProxy.Middleware
{
    public interface ISpnClient
    {
        Task<List<string>> GetAllSpn(CancellationToken cancellationToken = default);
        Task<bool> AddSpn(string spn);
        Task<bool> DeleteSpn(string spn);
    }
}