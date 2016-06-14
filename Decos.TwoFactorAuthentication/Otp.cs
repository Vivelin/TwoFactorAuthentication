using System;
using System.Security.Cryptography;

namespace Decos.TwoFactorAuthentication
{
    /// <summary>
    /// Provides methods for generating and validating time-based and HMAC-based one-time passwords.
    /// </summary>
    public static class Otp
    {
        /// <summary>
        /// The Unix time from which to start counting time steps.
        /// </summary>
        /// <remarks>
        /// Some apps, such as Google Authenticator, only support the default value of 0.
        /// </remarks>
        public const long Epoch = 0;

        /// <summary>
        /// The hash implementation to use in computing HMAC.
        /// </summary>
        /// <remarks>
        /// Some apps, such as Google Authenticator, only support SHA1-based HMAC.
        /// </remarks>
        public const string HmacAlgorithm = "SHA1";

        /// <summary>
        /// The number of bits used in generating shared secret keys.
        /// </summary>
        /// <remarks>
        /// Values lower than 80 do not seem to be supported by Google Authenticator. RFC 6238
        /// states that the key should be of the same length as the HMAC output, i.e. 160 when using
        /// HMACSHA1.
        /// </remarks>
        public const int SecretStrength = 80;

        /// <summary>
        /// The time step in seconds.
        /// </summary>
        /// <remarks>
        /// Some apps, such as Google Authenticator, only support the default value of 30.
        /// </remarks>
        public const int TimeStep = 30;

        /// <summary>
        /// The number of digits in a token.
        /// </summary>
        /// <remarks>Some apps, such as Google Authenticator, only support 6 digit tokens.</remarks>
        public const int TokenLength = 6;

        /// <summary>
        /// Generates a cryptographically strong secret key.
        /// </summary>
        /// <returns>A byte array containing the generated shared secret.</returns>
        public static byte[] GenerateSecret()
        {
            byte[] buffer = new byte[SecretStrength / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
            return buffer;
        }

        /// <summary>
        /// Computes the hash-based message authentication code (HMAC) for the specified message and
        /// shared secret.
        /// </summary>
        /// <param name="secret">The shared secret key to use in the hash algorithm.</param>
        /// <param name="message">The message to be authenticated.</param>
        /// <returns>A byte array containing the 160-bits computed hash.</returns>
        public static byte[] GetHmac(byte[] secret, byte[] message)
        {
            using (var hmacAlgorithm = HMAC.Create("HMAC" + HmacAlgorithm))
            {
                hmacAlgorithm.Key = secret;
                return hmacAlgorithm.ComputeHash(message);
            }
        }

        /// <summary>
        /// Returns a HMAC-based one-time password using the specified shared secret and counter
        /// value.
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
            byte[] message = Utility.GetBytes(counter);
            byte[] hmac = GetHmac(secret, message);
            int hotp = Truncate(hmac);
            return GetToken(hotp);
        }

        /// <summary>
        /// Returns a time-based one-time password using the specified shared secret.
        /// </summary>
        /// <param name="secret">The shared secret key.</param>
        /// <returns>
        /// A string containing the one-time password, consisting of a number of digits (as defined
        /// by <see cref="TokenLength"/>).
        /// </returns>
        /// <remarks>The TOTP algorithm is described in RFC 6238.</remarks>
        public static string GetTotp(byte[] secret)
        {
            return GetTotp(secret, 0);
        }

        /// <summary>
        /// Returns a past or future time-based one-time password using the specified shared secret.
        /// </summary>
        /// <param name="secret">The shared secret key.</param>
        /// <param name="offset">The number of time steps to look ahead or behind.</param>
        /// <returns>
        /// A string containing the one-time password, consisting of a number of digits (as defined
        /// by <see cref="TokenLength"/>).
        /// </returns>
        /// <remarks>The TOTP algorithm is described in RFC 6238.</remarks>
        public static string GetTotp(byte[] secret, int offset)
        {
            long steps = (DateTime.UtcNow.ToUnixTime() - Epoch) / TimeStep;
            return GetHotp(secret, steps + offset);
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
