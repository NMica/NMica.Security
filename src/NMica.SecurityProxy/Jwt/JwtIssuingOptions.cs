using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;

namespace NMica.SecurityProxy.Jwt;

[PublicAPI]
public class JwtIssuingOptions
{
    public SecurityKey? SigningKey { get; set; }
}