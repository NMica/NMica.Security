using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace NMica.SecurityProxy.Jwt
{
    public class SigningKeyCredentialsProvider : ISigningCredentialStore, IValidationKeysStore
    {
        private readonly IOptionsMonitor<JwtIssuingOptions> _options;

        public SigningKeyCredentialsProvider(IOptionsMonitor<JwtIssuingOptions> options)
        {
            _options = options;
        }

        public Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            var key = _options.CurrentValue.SigningKey;
            return Task.FromResult(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        }

        public async Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            var credentials = await GetSigningCredentialsAsync();
            return new[] {new SecurityKeyInfo {Key = credentials.Key, SigningAlgorithm = credentials.Algorithm}};
        }
    }
}
