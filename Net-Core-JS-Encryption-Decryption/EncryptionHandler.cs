using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

/*
 * .NET Core to / from JavaScript Encryption / Decryption
 * (c) by Smart In Media 2019 / Dr. Martin Weihrauch
 * Under MIT License
 *
 *
 *
 */

namespace Net_Core_JS_Encryption_Decryption
{
    public static class EncryptionHandler
    {
        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;

        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        
        /* This method not only returns ciphertext, but also the IV and the SALT, 
           which is important for the deciphering on the JS side. Having the same 
           IV and same SALT as suggested by demos on Stackoverflow, etc, is detrimental
           to the security. IV and SALT can be sent openly alongside ciphertext. An
           attacker cannot make anything with IV and SALT without the password.
           Explanation: With different IV, the same plaintext always results in different
           ciphertexts. With different SALTS, the same password always results in different
           ciphertexts. The ciphertext will look like this (byte array):
           SALT (32 bytes) + IV (16 bytes) + Ciphertext (N bytes) ---> whole thing in Base64
        */



        public static string Encrypt(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  

            var myRijndael = new RijndaelManaged();
            myRijndael.BlockSize = 128;
            myRijndael.KeySize = Keysize;
            myRijndael.IV = GenerateXBytesOfRandomEntropy(16); //IV must be 16 bytes / 128 bit
            myRijndael.Padding = PaddingMode.PKCS7;
            myRijndael.Mode = CipherMode.CBC;
            var salt = GenerateXBytesOfRandomEntropy(32);
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), salt,
                DerivationIterations);
            myRijndael.Key = rfc2898.GetBytes(Keysize / 8);
            byte[] utf8Text = new System.Text.UTF8Encoding().GetBytes(plainText);
            ICryptoTransform transform = myRijndael.CreateEncryptor();
            byte[] cipherText = transform.TransformFinalBlock(utf8Text, 0, utf8Text.Length);
            var cipherWithSaltAndIv = Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(myRijndael.IV) + ":" +
                                      Convert.ToBase64String(cipherText);
            
            return cipherWithSaltAndIv;
        }

        public static string Decrypt(string encryptedData, string passPhrase)
        {
            string[] parts = encryptedData.Split(":");
            var myRijndael = new RijndaelManaged();
            myRijndael.BlockSize = 128;
            myRijndael.KeySize = Keysize;
            myRijndael.IV = Convert.FromBase64String(parts[1]);//Encoding.UTF8.GetBytes("1234567890123456");
            myRijndael.Padding = PaddingMode.PKCS7;
            myRijndael.Mode = CipherMode.CBC;
            var salt = Convert.FromBase64String(parts[0]);//  Encoding.UTF8.GetBytes("12345678901234567890123456789012"); //GenerateXBytesOfRandomEntropy(32);
            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), salt,
                DerivationIterations);
            myRijndael.Key = rfc2898.GetBytes(Keysize / 8);
            var encryptedBytes = Convert.FromBase64String(parts[2]);
            ICryptoTransform transform = myRijndael.CreateDecryptor();
            byte[] cipherText = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            return System.Text.Encoding.UTF8.GetString(cipherText);
           
        }

        public static byte[] GenerateXBytesOfRandomEntropy(int x)
        {
            var randomBytes = new byte[x]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }

    }
}
