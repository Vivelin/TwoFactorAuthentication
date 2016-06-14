using System;
using System.Security.Cryptography;

namespace Decos.TwoFactorAuthentication
{
    /// <summary>
    /// Provides methods for generating time-based and HMAC-based one-time passwords.
    /// </summary>
    public static class Otp
    {
        // Note: while these constants could be configurable, Google Authenticator (among others)
        // only supports these defaults.

        /// <summary>
        /// The HMAC implementation to use.
        /// </summary>
        public const string HmacAlgorithm = "HMACSHA1";

        /// <summary>
        /// The number of digits in a token.
        /// </summary>
        public const int TokenLength = 6;

        /// <summary>
        /// Computes the hash-based message authentication code (HMAC) for the specified message and
        /// shared secret.
        /// </summary>
        /// <param name="secret">The shared secret key to use in the hash algorithm.</param>
        /// <param name="message">The message to be authenticated.</param>
        /// <returns>A byte array containing the 160-bits computed hash.</returns>
        public static byte[] GetHmac(byte[] secret, byte[] message)
        {
            using (var hmacAlgorithm = HMAC.Create(HmacAlgorithm))
            {
                hmacAlgorithm.Key = secret;
                return hmacAlgorithm.ComputeHash(message);
            }
        }

        /// <summary>
        /// Returns a HMAC-based one-time password using the specified shared secret and counter.
        /// </summary>
        /// <param name="secret">The shared secret key.</param>
        /// <param name="counter">
        /// An 8-byte counter value that must be synchronized between the client and server.
        /// </param>
        /// <returns>
        /// A string containing the one-time password, consisting of a number of digits (as defined
        /// by <see cref="TokenLength"/>).
        /// </returns>
        /// <remarks>The HTOP algorithm is described in RFC 4226.</remarks>
        public static string GetHotp(byte[] secret, long counter)
        {
            byte[] message = BitConverter.GetBytes(counter);
            byte[] hmac = GetHmac(secret, message);
            int hotp = Truncate(hmac);
            return GetToken(hotp);
        }

        /// <summary>
        /// Returns a usable token for the specified one-time password.
        /// </summary>
        /// <param name="otp">The one-time password bits to get a token from.</param>
        /// <returns>
        /// An string consisting of a number of digits as defined by <see cref="TokenLength"/>.
        /// </returns>
        private static string GetToken(int otp)
        {
            int modulus = (int)Math.Pow(10, TokenLength);
            int value = otp % modulus;
            return value.ToString().PadLeft(TokenLength, '0');
        }

        /// <summary>
        /// Extracts an integer from the specified hash.
        /// </summary>
        /// <param name="hash">The hash to truncate.</param>
        /// <returns>A 31-bit integer extracted from the hash using dynamic truncation.</returns>
        private static int Truncate(byte[] hash)
        {
            // Dynamic truncation
            int offset = hash[hash.Length - 1] & 0xF;
            int truncatedHash = 0;
            for (int i = 0; i < 4; ++i)
            {
                truncatedHash <<= 8;
                truncatedHash |= hash[offset + i];
            }

            // Mask the most-significant bit to avoid confusion about signed vs. unsigned operations
            return truncatedHash & 0x7fffffff;
        }
    }
}
