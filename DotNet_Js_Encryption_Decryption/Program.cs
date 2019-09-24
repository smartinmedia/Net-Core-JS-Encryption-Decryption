using System;
using System.Diagnostics;
using System.IO;
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
            Console.WriteLine("Encrypted text 'This is my secret text' with password 'This_is_my_password!': " + enc);

            var dec3 = EncryptionHandler.Decrypt(enc, passPhrase);
            Console.WriteLine("And decrypting again: " + dec3);
            Console.WriteLine("Please start the index.html to see the same in Javascript. Encryption / Decryption run in both ways and can be interchanged between C# and JS!");



        }
    }
}
