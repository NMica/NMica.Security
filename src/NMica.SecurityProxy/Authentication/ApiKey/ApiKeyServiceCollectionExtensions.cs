using System.Security.Claims;
using AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Authentication;

namespace NMica.SecurityProxy.Authentication.ApiKey;

public static class ApiKeyServiceCollectionExtensions
{
    public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, string keyName, string value)
    {
        return builder.AddApiKeyInHeaderOrQueryParams(options =>
        {
            options.SuppressWWWAuthenticateHeader = true;
            options.KeyName = keyName;
            options.Events.OnValidateKey = (context) =>
            {
                var configuration = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                var apiKey = configuration.GetValue<string>("ApiKey");
                var isValid = apiKey?.Equals(context.ApiKey, StringComparison.OrdinalIgnoreCase) ?? false;
                if (isValid)
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity(apiKey));
                    context.Success();
                }
                else
                {
                    context.NoResult();
                }
                return Task.CompletedTask;
            };
        });
    }
}