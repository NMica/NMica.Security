using System.DirectoryServices.Protocols;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using NMica.AspNetCore.Authentication.Spnego.Ldap;

namespace NMica.SpnManager.Controllers;

[ApiController]
[Route("[controller]")]
public class SpnController : ControllerBase
{

    private readonly ILogger<SpnController> _logger;
    private readonly LdapConnection _connection;
    private readonly SpnManagementOptions _options;

    public SpnController(ILogger<SpnController> logger, LdapConnection connection, IOptionsSnapshot<SpnManagementOptions> options)
    {
        _logger = logger;
        _connection = connection;
        _options = options.Value;
    }

    [HttpGet]
    [Authorize(KnownPolicies.ViewSpn)]
    public async Task<ActionResult<string[]>> GetAll()
    {
        if (!TryParseUsername(User.Identity?.Name, out var accountName))
        {
            throw new Exception("User identity is not established");
        }
        var searchRequest = new SearchRequest(_options.LdapQuery,$"(sAMAccountName={accountName})", SearchScope.Subtree, null);
        var searchResults = await _connection.PerformPagedSearch(searchRequest);
        if (!searchResults.Any())
            return NotFound();
        var spns = searchResults.First().GetStringArray(LdapAttribute.ServicePrincipalName);
        return spns;
    }
    
    [HttpGet("{service}/{hostname}")]
    [Authorize(KnownPolicies.ViewSpn)]
    public async Task<ActionResult<string?>> Get(string service, string hostname)
    {
        var spn = $"{service}/{hostname}";
        if (!TryParseUsername(User.Identity?.Name, out var accountName))
        {
            throw new Exception("User identity is not established");
        }
        var searchRequest = new SearchRequest(_options.LdapQuery,$"(sAMAccountName={accountName})", SearchScope.Subtree, null);
        var searchResults = await _connection.PerformPagedSearch(searchRequest);
        if (!searchResults.Any())
        {
            return NotFound();
        }

        var spns = searchResults.First().GetStringArray(LdapAttribute.ServicePrincipalName);

        if (!spns.Contains(spn))
        {
            return NotFound();
        }
        return spn;
    }
    
    [HttpPost("{service}/{hostname}")]
    [Authorize(KnownPolicies.EditSpn)]
    public async Task<ActionResult> Add(string service, string hostname)
    {
        var spn = $"{service}/{hostname}";
        var user = await GetUserFromLdap();
        if (user == null)
        {
            return NotFound($"Caller {User.Identity!.Name} not found via LDAP query");
        }

        if (user.GetStringArray("servicePrincipalName").Contains(spn))
        {
            return Ok();
        }
        var modRequest = new ModifyRequest(user.DistinguishedName, DirectoryAttributeOperation.Add, LdapAttribute.ServicePrincipalName, spn);
        var response = await _connection.ExecuteRequest<ModifyResponse>(modRequest);
        if (response.ResultCode == ResultCode.Success)
        {
            return Created(Request.GetEncodedUrl(), spn);

        }

        throw new Exception(response.ErrorMessage);
    }
    [HttpDelete("{service}/{hostname}")]
    [Authorize(KnownPolicies.EditSpn)]
    public async Task<ActionResult> Delete(string service, string hostname)
    {
        var spn = $"{service}/{hostname}";
        var user = await GetUserFromLdap();
        if (user == null)
        {
            return NotFound($"Caller {User.Identity!.Name} not found via LDAP query");
        }

        if (user.GetStringArray("servicePrincipalName").Contains(spn))
        {
            return Ok();
        }
        
        var modRequest = new ModifyRequest(user.DistinguishedName, DirectoryAttributeOperation.Delete, LdapAttribute.ServicePrincipalName, spn);
        var response = await _connection.ExecuteRequest<ModifyResponse>(modRequest);
        if (response.ResultCode == ResultCode.Success)
        {
            return Created(Request.GetEncodedUrl(), spn);
        }

        throw new Exception(response.ErrorMessage);
    }

    private async Task<SearchResultEntry?> GetUserFromLdap()
    {
        if (!TryParseUsername(User.Identity?.Name, out var accountName))
        {
            throw new Exception("User identity is not established");
        }
        var searchRequest = new SearchRequest(_options.LdapQuery,$"(sAMAccountName={accountName})", SearchScope.Subtree, null);
        var searchResults = await _connection.PerformPagedSearch(searchRequest);
        
        return searchResults.FirstOrDefault();
    }

    private bool TryParseUsername(string? domainUser, out string username)
    {
        username = string.Empty;
        if (domainUser == null)
            return false;
        var emailFormatComponents = domainUser.Split("@"); // user@domain.com
        if (emailFormatComponents.Length == 2)
        {
            username = emailFormatComponents[0];
            return true;
        }
        var legacyUsernameComponents = domainUser.Split(@"\"); // DOMAIN\user
        if (emailFormatComponents.Length == 2)
        {
            username = legacyUsernameComponents[1];
            return true;
        }

        return false;
    }
}