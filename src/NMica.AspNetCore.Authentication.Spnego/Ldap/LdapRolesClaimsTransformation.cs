using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    /// <summary>
    /// Transforms current security principal by converting SIDs to AD role names. Mapping is loaded on startup from LDAP
    /// </summary>
    [SuppressMessage("Interoperability", "CA1416", MessageId = "Validate platform compatibility")]
    public class LdapRolesClaimsTransformer : IStartupFilter, IClaimsTransformation
    {
        private readonly SemaphoreSlim _lock = new(1);
        private readonly ILogger<LdapRolesClaimsTransformer> _logger;
        private Dictionary<string, string> _sidsToGroupNames = new();
        private Dictionary<string, List<string>> _groupSidHierarchy = new();
        private DateTime _lastRefreshTime;
        private Timer? _refreshTimer;
        private readonly IOptionsMonitor<LdapOptions> _options;
        private bool _isInitialized;
        private LdapConnection _connection;

        public string Name { get; }


        public LdapRolesClaimsTransformer(
            IOptionsMonitor<LdapOptions> options,
            ILogger<LdapRolesClaimsTransformer> logger,
            string name = "")
        {
            Name = name;
            _options = options;
            _logger = logger;
            _connection = new LdapConnection(new LdapDirectoryIdentifier("")); // will be set properly during initialize call
        }

        private void Initialize()
        {
            _isInitialized = true;
            OnConfigChange();
        }

        private void OnConfigChange()
        {
            _refreshTimer?.Dispose();
            try
            {
                var options = _options.Get(Name);
                _connection = GetConnection(options);
                Task.Run(() => RefreshGroups(options)).ConfigureAwait(false);
                _refreshTimer?.Dispose();
                _refreshTimer = new Timer(_ => Task.Run(CheckGroupChanges), null, options.RefreshFrequency, options.RefreshFrequency);
            }
            catch (OptionsValidationException e)
            {

                _logger.LogWarning("AD group principal enrichment is disabled because LDAP options isn't properly configured.\n{Error}", string.Join("\n",e.Failures));
            }
        }

        private async Task RefreshGroups(LdapOptions options)
        {

            try
            {

                var attributes = new[]{"objectSid", "sAMAccountName", "distinguishedName","memberOf"};
                var searchRequest = new SearchRequest(options.GroupsQuery!, options.GroupsFilter, SearchScope.Subtree, attributes);
                var groups = await _connection.PerformPagedSearch(searchRequest);
                
                _lastRefreshTime = DateTime.UtcNow;
                var dc = Regex.Match(options.GroupsQuery!,@"DC=.+").Value;
                var builtinQuery = $"CN=Builtin,{dc}";
                searchRequest = new SearchRequest(builtinQuery, options.GroupsFilter, SearchScope.Subtree, attributes);
                var builtinGroups = await _connection.PerformPagedSearch(searchRequest);
                var groupsByDn = groups
                    .Concat(builtinGroups)
                    .Select(x => new SimpleGroup
                    {
                        Sid = x.GetSidString(),
                        sAMAccountName = x.GetAttributeValue("sAMAccountName"),
                        DistinguishedName = x.GetAttributeValue("distinguishedName"),
                        MemberOfDNs = x.GetStringArray("memberOf")
                    })
                    .ToDictionary(x => x.DistinguishedName);
                var simpleGroups = groupsByDn.Values;
                var loadedDNs = new HashSet<string>(groupsByDn.Keys);
                // algo summary:
                // 1. create dictionary of group to hashset of belongsTo
                // 2. create a dictionary of group to ALL parent hashsets it maintains (from step 1)
                // 3. flatten hashsets into a single Dictionary<string,HashSet<string>> and remove self from belongTo
                // 4. convert dictionary to sid based mapping for use at runtime
                // this algo is necessary because groups can have a circular relationship, which can cause stack burst if hashset buckets are not used

                // 1
                var directGroups = simpleGroups.ToDictionary(x => x.DistinguishedName, x =>
                {
                    // filter out member names we haven't loaded from ldap
                    var memberDNs = new HashSet<string>(x.MemberOfDNs);
                    memberDNs.IntersectWith(loadedDNs);
                    return memberDNs;
                });

                // 2
                var groupBelongToSet = new Dictionary<string, HashSet<HashSet<string>>>();
                HashSet<HashSet<string>> ResolveGroupHierarchy(SimpleGroup group)
                {
                    if (groupBelongToSet.TryGetValue(group.DistinguishedName, out var result))
                    {
                        return result;
                    }

                    result = new() {directGroups[group.DistinguishedName]};
                    groupBelongToSet.Add(group.DistinguishedName, result);
                    foreach (var memberOfDn in group.MemberOfDNs)
                    {
                        if (!groupsByDn.TryGetValue(memberOfDn, out var memberGroup))
                        {
                            continue; // this group is listed as memberOf, but we haven't loaded it as part of LDAP (probably part of some other OU). skip
                        }

                        if(!groupBelongToSet.TryGetValue(memberOfDn, out var inheritedGroups))
                        {
                            inheritedGroups = ResolveGroupHierarchy(memberGroup);
                        }
                        result.UnionWith(inheritedGroups);
                    }

                    return result;
                }
                foreach (var group in simpleGroups)
                {
                    ResolveGroupHierarchy(group);
                }

                // 3
                var groupDnHierarchy = groupBelongToSet.ToDictionary(x => x.Key, x => x.Value.Aggregate(new HashSet<string>(), (accumulator, bucket) =>
                {
                    accumulator.UnionWith(bucket);
                    return accumulator;
                }));

                foreach (var (group, belongsTo) in groupDnHierarchy)
                {
                    belongsTo.Remove(group);
                }

                try
                {
                    _lock.Release();
                    _sidsToGroupNames = simpleGroups.ToDictionary(x => x.Sid, x => x.sAMAccountName);
                    // 4. convert groupHierarchy to sid based mapping
                    _groupSidHierarchy = groupDnHierarchy.ToDictionary(kv => groupsByDn[kv.Key].Sid, kv => kv.Value.Select(x => groupsByDn[x].Sid).ToList());
                    var groupCount = _sidsToGroupNames.Count;
                    _logger.LogInformation("Loaded {GroupCount} groups from LDAP", groupCount);

                }
                finally
                {
                    _lock.Release();
                }
            }
            catch (Exception e)
            {
                _logger.LogError("Failed to load groups from LDAP\n{Error}", e);
            }
        }

        private async Task CheckGroupChanges()
        {
            try
            {
                var options = _options.Get(Name);
                var updatesFilter = $"(&{options.GroupsFilter}(whenChanged>={_lastRefreshTime:yyyyMMddHHmmss}.0Z))";
                var attributes = new[] {"objectSid"};
                _logger.LogTrace("Checking if LDAP groups have changed");

                var searchRequest = new SearchRequest(options.GroupsQuery!, updatesFilter, SearchScope.Subtree, attributes);
                searchRequest.Controls.Add(new PageResultRequestControl(1));
                var searchResponse = (SearchResponse) await Task<DirectoryResponse>.Factory.FromAsync(
                    _connection.BeginSendRequest,
                    _connection.EndSendRequest,
                    searchRequest,
                    PartialResultProcessing.NoPartialResultSupport,
                    null);

                var isUpdated = searchResponse.Entries.Count > 0;
                if (isUpdated)
                {
                    _logger.LogInformation("Detected changes to LDAP groups since last refresh");
                    await RefreshGroups(options);
                }
            }
            catch (OptionsValidationException)
            {
                // ignore (validation will be handled by callback of config change)
            }
            catch (Exception e)
            {
                _logger.LogError("Failed to check for group changes\n{Error}", e);
            }
        }

        private LdapConnection GetConnection(LdapOptions options)
        {
            var di = new LdapDirectoryIdentifier(server: options.Host, options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
            var connection = new LdapConnection(di, options.Credentials, AuthType.Basic);
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.ProtocolVersion = 3; //Setting LDAP Protocol to latest version
            connection.Timeout = TimeSpan.FromMinutes(1);
            if (options.UseSsl)
            {
                connection.SessionOptions.SecureSocketLayer = options.UseSsl;
                if (!options.ValidateServerCertificate)
                {
                    if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                    {
                        connection.SessionOptions.VerifyServerCertificate = (ldapConnection, certificate) => true;
                    }
                    else if (!Environment.GetEnvironmentVariables().Contains("LDAPTLS_REQCERT"))
                    {
                        _logger.LogWarning("LDAPS certificate validation is disabled in config, but LDAPTLS_REQCERT environmental variable is not set. On non-Windows environments certificate validation must be disabled by setting environmental variable LDAPTLS_REQCERT to 'never'");
                    }
                }
            }

            
            connection.Bind();
            return connection;
        }

        private async Task AcquireLock()
        {
            while (!await _lock.WaitAsync(TimeSpan.FromMilliseconds(100)))
            {
                Thread.Yield();
            }
        }
       

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return builder =>
            {
                Initialize();
                _options.OnChange(_ => Initialize());
                next(builder);
            };
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var options = _options.Get(Name);
            if (!_isInitialized)
            {
                throw new InvalidOperationException($"{GetType().Name} has not been initialized");
            }
            if (principal.Identity == null || options.Claims.Count == 0)
            {
                return principal;
            }

            await AcquireLock();
            try
            {
                if (options.Claims.Any(x => x.LdapAttribute == "memberof"))
                {
                    ReplaceGroupSidsWithNames(principal);
                }

                await EnrichUserAttributeClaims(principal, options);

                return principal;
            }
            finally
            {
                _lock.Release();
            }
        }

        private async Task EnrichUserAttributeClaims(ClaimsPrincipal principal, LdapOptions options)
        {
            var userSid = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Sid)?.Value;

            if (userSid == null)
            {
                return;
            }
            
            var attributesMap = options.Claims.Where(x => x.LdapAttribute != "memberof").ToArray();
            if (!attributesMap.Any())
            {
                return;
            }

            var attributesToLoad = attributesMap.Select(x => x.LdapAttribute).ToArray();

            
            var searchRequest = new SearchRequest(options.UsersQuery, $"(objectSid={userSid})", SearchScope.Subtree, attributesToLoad);
            var searchResponse = (SearchResponse) await Task<DirectoryResponse>.Factory.FromAsync(
                _connection.BeginSendRequest,
                _connection.EndSendRequest,
                searchRequest,
                PartialResultProcessing.NoPartialResultSupport,
                null);


            var userLdapEntry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault();
            if (userLdapEntry == null)
            {
                _logger.LogWarning("Unable to enrich user with claims as LDAP search for user's sid produced no results");
                return;
            }

            var identity = (ClaimsIdentity)principal.Identity!;
            var usersAttributes = userLdapEntry.Attributes;
            foreach (var claimMapping in attributesMap)
            {
                if (usersAttributes.Contains(claimMapping.LdapAttribute))
                {
                    var attribute = usersAttributes[claimMapping.LdapAttribute];
                    foreach (var attributeValue in attribute)
                    {
                        if (attributeValue == null)
                        {
                            continue;
                        }

                        var attributeValueStr = attributeValue switch
                        {
                            byte[] bytes => Encoding.UTF8.GetString(bytes),
                            string str => str,
                            { } other => other.ToString()
                        };
                        identity.AddClaim(new Claim(claimMapping.ClaimType, attributeValueStr!));
                    }
                    
                }
            }
        }

        private void ReplaceGroupSidsWithNames(ClaimsPrincipal principal)
        {
            var identity = (ClaimsIdentity) principal.Identity!;
            var claimsToAdd = identity.Claims
                .Where(x => x.Type == ClaimTypes.GroupSid)
                .Select(x => x.Value)
                .SelectMany(sid =>
                {
                    if (!_groupSidHierarchy.TryGetValue(sid, out var belongToSids))
                    {
                        belongToSids = new List<string>();
                    }

                    var allGroupSids = belongToSids.Union(new[] {sid});
                    return allGroupSids;
                })
                .Distinct()
                .Select(sid => _sidsToGroupNames.GetValueOrDefault(sid))
                .Where(groupName => groupName != null)
                .Where(groupName => !identity.HasClaim(ClaimTypes.Role, groupName!))
                .Select(groupName => new Claim(ClaimTypes.Role, groupName!))
                .ToList();
            identity.AddClaims(claimsToAdd);

            // remove all sid based claims
            var claimsToRemove = identity.Claims.Where(x => x.Type == ClaimTypes.GroupSid).ToArray();
            foreach (var claim in claimsToRemove)
            {
                identity.RemoveClaim(claim);
            }
        }
        
        

        private struct SimpleGroup
        {
            public string Sid { get; init; }
            // ReSharper disable once InconsistentNaming
            public string sAMAccountName { get; init; }
            public string DistinguishedName { get; init; }
            public string[] MemberOfDNs { get; init; }
        }
    }
}
