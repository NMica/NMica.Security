using System.CommandLine;
using System.CommandLine.Builder;
using KerberosUtil.Commands;

namespace KerberosUtil;

public static class PromptMiddleware
{
    public static CommandLineBuilder UsePrompt(this CommandLineBuilder builder)
    {
        return builder.UseMiddleware(async (ctx, next) =>
            {
                // add support for prompting for any params that are required but not specified
                if (ctx.BindingContext.ParseResult.ValueForOption<bool>("--prompt"))
                {
                    var optionsToPrompt = ctx.ParseResult.CommandResult.Command.Options
                        .OfType<Option>()
                        .Where(x => x.IsRequired && ctx.ParseResult.RootCommandResult.FindResultFor(x) is null)
                        .ToList();
                    var args = new List<string>(ctx.ParseResult.Tokens.Select(x => x.Value.ToString()));
                    foreach (var option in optionsToPrompt)
                    {
                        Console.WriteLine($"{option.Name.ToOptionName()}: ");
                        var argName = $"--{option.Name.ToArgName()}";
                        var value = "";
                        while (string.IsNullOrEmpty(value))
                        {
                            value = Console.ReadLine();
                        }

                        args.Add(argName);
                        args.Add(value);
                    }

                    ctx.ParseResult = ctx.Parser.Parse(args);
                }

                await next(ctx);
            });
    }
    
}