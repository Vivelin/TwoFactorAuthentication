using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decos.TwoFactorAuthentication;

namespace TestTotp
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] secret = Otp.GenerateSecret();
            string key = Utility.Base32Encode(secret);
            Console.WriteLine("Your shared secret key: " + key);

            Console.WriteLine("Press Ctrl+C to exit.");
            while (true)
            {
                Console.Write("Token: ");

                string token = Otp.GetTotp(secret);

                var c = Console.BackgroundColor;
                Console.BackgroundColor = Console.ForegroundColor;
                Console.ForegroundColor = c;
                Console.Write(token);
                Console.ResetColor();

                Console.Write("\r");

                System.Threading.Thread.Sleep(1000);
            }
        }
    }
}
