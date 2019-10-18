using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using CryptSharp.Utility;
using Net_Core_JS_Encryption_Decryption;


namespace DotNet_Js_Encryption_Decryption
{
/*
 * .NET Core to / from JavaScript Encryption / Decryption
 * (c) by Smart In Media 2019 / Dr. Martin Weihrauch
 * Under MIT License
 *
 *
 *
 */
    class Program
    {
        static void Main(string[] args)
        {

            //Encrypt plain text in C# with a random password
            string plainText = "This is my secret text!";
            //You can also use the built in password generator!!
            string passPhrase = PasswordGenerator.GenerateRandomPassword(20);
            passPhrase = "This_is_my_password!";

            var enc = EncryptionHandler.Encrypt(plainText, passPhrase);
            Console.WriteLine("Plaintext: 'This is my secret text' with password 'This_is_my_password!' results in ciphertext: " + enc);

            var dec3 = EncryptionHandler.Decrypt(enc, passPhrase);
            Console.WriteLine("And decrypting again: " + dec3);
            Console.WriteLine("Please start the index.html to see the same in Javascript. Encryption / Decryption run in both ways and can be interchanged between C# and JS!");

            /*
             * Testing Scrypt 
             * The recommended parameters for interactive logins as of 2009 are
             * iterationCount=16384, blockSize=8, threadCount=1, those are the default values.
             * They should be increased as memory latency and CPU parallelism increases.
             */

            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();
            
            // NOW RUNNING SCRYPT
            string hashString = ScryptHandler.Hash(passPhrase, "This_is_my_SALT!", 16384);
            stopWatch.Stop();

            Console.WriteLine("\r\nTesting Scrypt with the password 'This_is_my_password!': " + hashString);
            bool compare = ScryptHandler.ComparePasswordWithHash("This_is_my_password!", hashString);
            if (compare)
            {
                Console.WriteLine("The password matches with the stored hash!");
            }
            else
            {
                Console.WriteLine("The password does not match with the stored hash!");
            }
            
            // Get the elapsed time as a TimeSpan value.
            TimeSpan ts = stopWatch.Elapsed;

            // Format and display the TimeSpan value.
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);
            Console.WriteLine("Time elapsed in HH:MM:SS (only for creating the hash, not checking): " + elapsedTime);
        }
        
    }
}
