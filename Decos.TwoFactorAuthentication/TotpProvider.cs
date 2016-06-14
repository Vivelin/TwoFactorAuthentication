using System;

namespace Decos.TwoFactorAuthentication
{
    /// <summary>
    /// Provides TOTP-based two-factor authentication for a single account.
    /// </summary>
    public class TotpProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TotpProvider"/> with the specified shared
        /// secret.
        /// </summary>
        /// <param name="secret">A byte array containing the shared secret key.</param>
        public TotpProvider(byte[] secret)
        {
            Secret = secret;
            Key = Utility.Base32Encode(secret);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TotpProvider"/> with the specified shared
        /// secret.
        /// </summary>
        /// <param name="key">A Base32 encoded string containing the shared secret key.</param>
        public TotpProvider(string key)
        {
            Secret = Utility.Base32Decode(key);
            Key = key;
        }

        /// <summary>
        /// Gets the Base32 encoded account key.
        /// </summary>
        public string Key { get; }

        /// <summary>
        /// Gets the shared secret key of the account.
        /// </summary>
        public byte[] Secret { get; }

        /// <summary>
        /// Returns a new <see cref="TotpProvider"/> class with a newly generated shared secret.
        /// </summary>
        /// <returns>A new instance of the <see cref="TotpProvider"/> class.</returns>
        public static TotpProvider CreateNew()
        {
            byte[] secret = Otp.GenerateSecret();
            return new TotpProvider(secret);
        }

        /// <summary>
        /// Returns the otpauth URI that can be used to generate QR codes for authenticator apps.
        /// </summary>
        /// <param name="label">
        /// The label used to identify which account the key is associated with.
        /// </param>
        /// <param name="issuer">
        /// The issuer indicating the provider or service the account is associated with.
        /// </param>
        /// <returns>
        /// A string representing the URI that can be used in QR code to set up authenticator apps.
        /// </returns>
        public string GetQRCodeUri(string label, string issuer)
        {
            return string.Format("otpauth://totp/{0}?issuer={1}&secret={2}&algorithm={3}&digits={4}&period={5}",
                Uri.EscapeDataString(label),
                Uri.EscapeDataString(issuer),
                Utility.Base32Encode(Secret),
                Uri.EscapeDataString(Otp.HmacAlgorithm),
                Uri.EscapeDataString(Otp.TokenLength.ToString()),
                Uri.EscapeDataString(Otp.TimeStep.ToString())
            );
        }

        /// <summary>
        /// Determines whether the provided time-based one-time password is valid.
        /// </summary>
        /// <param name="token">The token to validate.</param>
        /// <param name="margin">
        /// The number of time steps that a one-time password may be too early or too late.
        /// </param>
        /// <returns>
        /// <c>true</c> if the token is valid within the provided time window; otherwise,
        /// <c>false</c>.
        /// </returns>
        public bool ValidateToken(string token, int margin = 1)
        {
            margin = Math.Abs(margin);

            // Note: not returning early to prevent a potential timing attack
            bool valid = false;
            for (int offset = -margin; offset <= margin; offset++)
            {
                if (token == Otp.GetTotp(Secret, offset))
                    valid = true;
            }
            return valid;
        }
    }
}
