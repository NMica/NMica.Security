using System.Net;

namespace NMica.SecurityProxy.Spn
{
    public class SpnClient : ISpnClient
    {
        private readonly HttpClient _client;

        public SpnClient(HttpClient client)
        {
            _client = client;
            _client.BaseAddress = new Uri(_client.BaseAddress!, "spn/");
        }

        public async Task<List<string>> GetAllSpn(CancellationToken cancellationToken = default)
        {
            return (await _client.GetFromJsonAsync<List<string>>("", cancellationToken))!;
        }

        public async Task<bool> AddSpn(string spn)
        {
            var responseMessage = await _client.PostAsync(spn, null);
            responseMessage.EnsureSuccessStatusCode();
            return responseMessage.StatusCode == HttpStatusCode.Created;
        }

        public async Task<bool> DeleteSpn(string spn)
        {
            var responseMessage = await _client.DeleteAsync(spn);
            responseMessage.EnsureSuccessStatusCode();
            return true;
        }
    }
}