using System;
using System.Text;
using Decos.TwoFactorAuthentication;

namespace TestBase32
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Press Ctrl+C to stop.");
            while (true)
            {
                Console.WriteLine();
                Console.Write("Input: ");
                string input = Console.ReadLine();

                byte[] data = Encoding.UTF8.GetBytes(input);
                Console.WriteLine("Input as byte array: " + BitConverter.ToString(data));

                string encoded = Utility.Base32Encode(data);
                Console.WriteLine("Encoded as base32: " + encoded);

                byte[] decoded = Utility.Base32Decode(encoded);
                Console.WriteLine("Decoded as base32: " + BitConverter.ToString(decoded));

                string output = Encoding.UTF8.GetString(decoded);
                if (output == input)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.BackgroundColor = ConsoleColor.DarkGreen;
                    Console.WriteLine("CORRECT");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.BackgroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("OUTPUT MISMATCH: " + output);
                    Console.ResetColor();
                }
            }
        }
    }
}
