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
            string plainText = "This is my secret text!";
            //You can also use the built in password generator!!
            string passPhrase = PasswordGenerator.GenerateRandomPassword(20);
            passPhrase = "This_is_my_password!";

            var enc = EncryptionHandler3.Encrypt(plainText, passPhrase);
            Console.WriteLine("Encrypted text from DEC3: " + enc);

            var dec3 = EncryptionHandler3.Decrypt(enc, passPhrase);
            Console.WriteLine("THIS IS FROM DEC3: " + dec3);


            /*
            var dec = EncryptionHandler2.DecryptStringAES();
            
            Console.WriteLine("RESULT: " + dec);


            string encryptedData = EncryptionHandler.Encrypt(plainText, passPhrase);

            Console.WriteLine(".NET Core and JavaScript Encryption Decryption Library\r\n(c) by Smart In Media, MIT License"
            + "\r\n\r\nThe plaintext: " + plainText + "\r\nThe passphrase: " + passPhrase 
            + "\r\n\r\nThe resulting ciphertext in base64: " + encryptedData);

            string decryptedCipher = EncryptionHandler.Decrypt(encryptedData, passPhrase);

            Console.WriteLine("\r\n\r\nNow let's decrypt this with C#:\r\n\r\nDecrypted plaintext: " + decryptedCipher);

            Console.WriteLine("\r\n\r\n------------------------------\r\nNow, press a key to start the browser and see if JavaScript can decrypt this! Else, just run the index.html provided with this example. It contains the JS!");
            Console.ReadKey();


            // Start a browser and see if it can be decrypted with JS
            var proc = Process.Start(@"cmd.exe ", @"/c index.html");
*/
        }
    }
}
