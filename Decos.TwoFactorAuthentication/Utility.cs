using System;
using System.Text;

namespace Decos.TwoFactorAuthentication
{
    /// <summary>
    /// Provides methods for working with one-time passwords.
    /// </summary>
    public static class Utility
    {
        /// <summary>
        /// A string containing the valid Base32 characters in ascending order.
        /// </summary>
        public const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <summary>
        /// An array of the characters to ignore when decoding a Base32-encoded string.
        /// </summary>
        public static readonly char[] Base32Ignore = new char[] { ' ', '\t', '\r', '\n', '-', '=' };

        /// <summary>
        /// Decodes a Base32 encoded string.
        /// </summary>
        /// <param name="value">The Base32 encoded string to decode.</param>
        /// <returns>A byte array containing the decoded value.</returns>
        public static byte[] Base32Decode(string value)
        {
            if (value == null) return null;

            int length = value.Length * 5 / 8;
            byte[] result = new byte[length];

            byte buffer = 0;
            int bitsRemaining = 8;
            int mask = 0;
            int count = 0;

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (Array.IndexOf(Base32Ignore, c) >= 0)
                    continue;

                c = (char)Base32Alphabet.IndexOf(c);
                if (c < 0)
                {
                    string message = "'{0}' is not a valid base32 character";
                    throw new ArgumentException(string.Format(message, value[i]));
                }

                if (bitsRemaining > 5)
                {
                    mask = c << (bitsRemaining - 5);
                    buffer = (byte)(buffer | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = c >> (5 - bitsRemaining);
                    buffer = (byte)(buffer | mask);
                    result[count++] = buffer;
                    buffer = (byte)(c << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            if (count < length)
            {
                result[count] = buffer;
            }
            return result;
        }

        /// <summary>
        /// Encodes a value to a Base32 string.
        /// </summary>
        /// <param name="data">A byte array containing the data to encode.</param>
        /// <returns>A string containing the Base32 encoded value.</returns>
        public static string Base32Encode(byte[] data)
        {
            return Base32Encode(data, 0, data.Length);
        }

        /// <summary>
        /// Encodes a subset of a value to a Base32 string.
        /// </summary>
        /// <param name="data">A byte array containing the data to encode.</param>
        /// <param name="offset">The offset in <paramref name="data"/>.</param>
        /// <param name="length">The number of elements to encode.</param>
        /// <returns>A string containing the Base32 encoded value.</returns>
        public static string Base32Encode(byte[] data, int offset, int length)
        {
            StringBuilder value = new StringBuilder();
            if (length > 0)
            {
                int buffer = data[offset];
                int next = offset + 1;
                int end = offset + length;
                int bitsLeft = 8;
                while (bitsLeft > 0 || next < end)
                {
                    if (bitsLeft < 5)
                    {
                        if (next < end)
                        {
                            buffer <<= 8;
                            buffer |= data[next++] & 0xFF;
                            bitsLeft += 8;
                        }
                        else
                        {
                            int pad = 5 - bitsLeft;
                            buffer <<= pad;
                            bitsLeft += pad;
                        }
                    }

                    int index = 0x1F & (buffer >> (bitsLeft - 5));
                    bitsLeft -= 5;
                    value.Append(Base32Alphabet[index]);
                }
            }
            return value.ToString();
        }
    }
}
