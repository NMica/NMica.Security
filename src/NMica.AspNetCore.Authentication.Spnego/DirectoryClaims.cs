using System;

namespace NMica.AspNetCore.Authentication.Spnego
{
    [Flags]
    public enum DirectoryClaims
    {
        None = 0,
        Groups = 1 << 0,
        GivenName = 1 << 1,
        FamilyName = 1 << 2,
        Email = 1 << 3,
        All = int.MaxValue,
    }
}