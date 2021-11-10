#nullable disable
using System.Text;
using JetBrains.Annotations;
using Kerberos.NET.Entities.Pac;

// ReSharper disable IdentifierTypo

namespace NMica.AspNetCore.Authentication.Spnego.Ldap
{
    [PublicAPI]
    internal class SecurityIdentifier
    {
        private readonly IdentifierAuthority _authority;
        private string _sddl;

        public SecurityIdentifier(IdentifierAuthority authority, int[] subs, SidAttributes attributes)
        {
            _authority = authority;
            SubAuthorities = subs;

            Attributes = attributes;

            BinaryForm = ToBinaryForm(authority, subs);
        }

        private static byte[] ToBinaryForm(IdentifierAuthority authority, int[] subs)
        {
            var binaryForm = new Memory<byte>(new byte[(1 + 1 + 6) + 4 * subs.Length]);

            binaryForm.Span[0] = 1; // revision
            binaryForm.Span[1] = (byte) subs.Length;

            Endian.ConvertToBigEndian((int) authority, binaryForm.Slice(4, 4));

            for (var i = 0; i < subs.Length; i++)
            {
                Endian.ConvertToLittleEndian(subs[i], binaryForm.Slice(8 + (4 * i), 4));
            }

            return binaryForm.ToArray();
        }

        public SecurityIdentifier(SecurityIdentifier sid, SidAttributes attributes)
            : this(sid._authority, sid.SubAuthorities, attributes)
        {
        }

        public SecurityIdentifier(byte[] binary, SidAttributes attributes = 0)
        {
            BinaryForm = binary;

            var span = new Span<byte>(binary);

            _authority = (IdentifierAuthority) span.Slice(2, 6).AsLong();
            Attributes = attributes;

            SubAuthorities = new int[binary[1]];

            for (var i = 0; i < SubAuthorities.Length; i++)
            {
                SubAuthorities[i] = (int) span.Slice(8 + (4 * i), 4).AsLong(littleEndian: true);
            }
        }

        public byte[] BinaryForm { get; }

        public SidAttributes Attributes { get; }

        public string Value
        {
            get { return ToString(); }
        }

        public int[] SubAuthorities { get; }

        public override string ToString()
        {
            if (_sddl == null)
            {
                var result = new StringBuilder();

                result.AppendFormat("S-1-{0}", (long) _authority);

                for (var i = 0; i < SubAuthorities.Length; i++)
                {
                    result.AppendFormat("-{0}", (uint) (SubAuthorities[i]));
                }

                _sddl = result.ToString().ToUpperInvariant();
            }

            return _sddl;
        }

        internal SecurityIdentifier AppendTo(SecurityIdentifier sidId)
        {
            var subs = sidId.SubAuthorities.Union(SubAuthorities).ToArray();

            return new SecurityIdentifier(sidId._authority, subs, Attributes);
        }
    }

    public static class ExtensionMethods
    {
        public static long AsLong(this byte[] val)
        {
            return AsLong((ReadOnlyMemory<byte>) val);
        }

        public static long AsLong(this ReadOnlySpan<byte> val, bool littleEndian = false)
        {
            var bytes = val.ToArray();

            if (littleEndian)
            {
                Array.Reverse(bytes);
            }

            long num = 0;

            for (var i = 0; i < bytes.Length; i++)
            {
                num = (num << 8) | bytes[i];
            }

            return num;
        }

        public static long AsLong(this Span<byte> val, bool littleEndian = false)
        {
            var bytes = val;

            return AsLong((ReadOnlySpan<byte>) bytes, littleEndian);
        }

        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            return AsLong(val.Span, littleEndian);
        }
    }
}
