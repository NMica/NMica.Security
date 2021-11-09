using System;
using System.CommandLine;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using Kerberos.NET.Credentials;

namespace KerberosUtil.Commands
{
    public static class CommandUtil
    {
        // public static Command FromOptions<TOptions>(string name = null) => FromOptions(typeof(TOptions), name);
        public static Command FromOptions(Type type, string name)
        {
            var command = new Command(name, type.Name.ToArgName());
            foreach (var property in type.GetProperties().Where(x => x.CanWrite))
            {
                var optionName = $"--{property.Name.ToArgName()}";
                var isRequired = property.GetCustomAttribute<RequiredAttribute>() != null;
                var description = property.GetCustomAttribute<DescriptionAttribute>()?.Description;
                var option = new Option(optionName, description, property.PropertyType)
                {
                    IsRequired = isRequired
                };
                command.AddOption(option);
            }

            return command;
        }

        public static string ToArgName(this string name) => string.Join("-", Regex.Matches(name, "[A-Z]*[a-z0-9]*").Select(x => x.Value.ToLower()).Where(x => x != ""));
        public static string ToOptionName(this string name) => string.Join("", Regex.Matches(name, @"\w+").Select(x => Regex.Replace(x.Value, @"^\w", c => c.Value.ToUpper().ToString())));
        
        public static KerberosPasswordCredential GetCredentials(string username, string password)
        {
            var split = username.Split("@");
            if (split.Length != 2)
            {
                throw new Exception("User must be in <user>@<domain> format");
            }
        
            return new KerberosPasswordCredential(split[0], password, split[1]);
        }
    }
}