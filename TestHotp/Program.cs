using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decos.TwoFactorAuthentication;

namespace TestHotp
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] secret = Otp.GenerateSecret();
            string key = Utility.Base32Encode(secret);
            Console.WriteLine("Your shared secret key: " + key);

            long counter = 0;
            string check = Otp.GetHotp(secret, counter);
            Console.WriteLine("Integrity check value: " + check);

            while (true)
            {
                Console.Write("Press enter to generate a new token, or Ctrl+C to exit...");
                Console.ReadLine();

                counter++;
                string token = Otp.GetHotp(secret, counter);

                var c = Console.BackgroundColor;
                Console.BackgroundColor = Console.ForegroundColor;
                Console.ForegroundColor = c;
                Console.Write(token);
                Console.ResetColor();

                Console.WriteLine(" {0}", counter);
            }
        }
    }
}
