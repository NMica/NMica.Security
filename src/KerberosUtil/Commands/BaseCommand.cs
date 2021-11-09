using System.CommandLine;
using JetBrains.Annotations;

namespace KerberosUtil.Commands
{
    [PublicAPI]
    public abstract class BaseCommand<TOptions> 
    {
        protected BaseCommand(TOptions options)
        {
            CommandOptions = options;
        }

        protected TOptions CommandOptions { get; }
        public abstract Task Run();
    }
    
}