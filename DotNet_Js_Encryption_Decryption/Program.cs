using System;
using System.Diagnostics;
using System.IO;
using Net_Core_JS_Encryption_Decryption;

namespace DotNet_Js_Encryption_Decryption
{
    class Program
    {
        static void Main(string[] args)
        {
            //Encrypt plain text in C# with a random password
            string plainText = "I want this text to be secret!";
            string passPhrase = PasswordGenerator.GenerateRandomPassword(20);
            string cipherTextBase64 = EncryptionHandler.Encrypt(plainText, passPhrase);

            Console.WriteLine(".NET Core and JavaScript Encryption Decryption Library\r\n(c) by Smart In Media, MIT License"
            + "\r\n\r\nThe plaintext: " + plainText + "\r\nThe passphrase: " + passPhrase 
            + "\r\n\r\nThe resulting ciphertext in base64: " + cipherTextBase64);

            string decryptedCipher = EncryptionHandler.Decrypt(cipherTextBase64, passPhrase);

            Console.WriteLine("\r\n\r\nNow let's decrypt this with C#:\r\n\r\nDecrypted plaintext: " + decryptedCipher);

            Console.WriteLine("\r\n\r\n------------------------------\r\nNow, press a key to start the browser and see if JavaScript can decrypt this!");
            Console.ReadKey();


            // Start a browser and see if it can be decrypted with JS
            var proc = Process.Start(@"cmd.exe ", @"/c index.html?ciphertext=" + cipherTextBase64 + "&" 
                                                  + "passphrase=" + passPhrase);

        }
    }
}
