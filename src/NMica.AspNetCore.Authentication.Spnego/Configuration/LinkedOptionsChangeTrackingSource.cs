using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace NMica.AspNetCore.Authentication.Spnego.Configuration
{
    /// <summary>
    /// Updates options of type <typeparamref cref="TOptions"/> when there's a change to options of type <typeparamref cref="TOptionsLink"/>
    /// </summary>
    /// <typeparam name="TOptions">Option type being configured</typeparam>
    /// <typeparam name="TOptionsLink">Options being monitored for changes</typeparam>
    [PublicAPI]
    public class LinkedOptionsChangeTrackingSource<TOptions, TOptionsLink> : IOptionsChangeTokenSource<TOptions>
    {
        private readonly IOptionsMonitor<TOptionsLink> _link;
        private CancellationTokenSource _cts = new();
        private CancellationChangeToken _cct;
        private object _lock = new();
        public LinkedOptionsChangeTrackingSource(IOptionsMonitor<TOptionsLink> link) : this(Options.DefaultName, link)
        {
        }

        public LinkedOptionsChangeTrackingSource(string name, IOptionsMonitor<TOptionsLink> link)
        {
            Name = name;
            _link = link;
            _link.OnChange(ReplaceChangeToken);
            _cct = new CancellationChangeToken(_cts.Token);
        }

        private void ReplaceChangeToken(TOptionsLink link, string name)
        {
            lock (_lock)
            {
                var prevCts = _cts;
                _cts = new CancellationTokenSource();
                _cct = new CancellationChangeToken(_cts.Token);
                prevCts.Cancel();
            }
        }

        public IChangeToken GetChangeToken() => _cct;

        public string Name { get; }
    }
}
