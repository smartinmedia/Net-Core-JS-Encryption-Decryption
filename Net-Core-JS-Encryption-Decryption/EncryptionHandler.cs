using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Net_Core_JS_Encryption_Decryption.Helpers;
using Newtonsoft.Json;

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

        /* This method not only returns ciphertext, but also the IV and the SALT, 
           which is important for the deciphering on the JS side. Having the same 
           IV and same SALT as suggested by demos on Stackoverflow, etc, is detrimental
           to the security. IV and SALT can be sent openly alongside ciphertext. An
           attacker cannot make anything with IV and SALT without the password.
           Explanation: With different IV, the same plaintext always results in different
           ciphertexts. With different SALTS, the same password always results in different
           ciphertexts. The ciphertext will be a JSON Object:
        */
        /*
        {
            "DerivationType": "scrypt", // optionally: rfc
            "Salt": "3a069e9126af66a839067f8a272081136d8ce63ed72176dc8a29973d2b15361f", //SALT must be in Hex
            "Cost": 16384, //only for DerivationType "scrypt", not for "rfc"
            "BlockSize": 8, //only for DerivationType "scrypt", not for "rfc"
            "Parallel": 1, //only for DerivationType "scrypt", not for "rfc"
            "KeySizeInBytes": 32,
            "DerivationIterations": 0 // Only for DerivationType "rfc", not needed for "scrypt"
            
        }
        */
        public static string Encrypt(string plainText, string passPhrase, PasswordDerivationOptions pO = null)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  

            
            var myRijndael = new RijndaelManaged();
            myRijndael.BlockSize = 128;
            myRijndael.IV = GenerateXBytesOfRandomEntropy(16); //IV must be 16 bytes / 128 bit
            myRijndael.Padding = PaddingMode.PKCS7;
            myRijndael.Mode = CipherMode.CBC;

            // Using Scrypt for Key Derivation
            if (pO == null || pO.DerivationType == "scrypt")
            {
                pO = new PasswordDerivationOptions();
                pO.DerivationType = "scrypt";
                myRijndael.Key =
                    ScryptHandler.GetOnlyHashBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), pO);
            }
            // Using RFC2898 for Key Derivation
            else
            {
                if (pO.Salt == null)
                {
                    pO.Salt = GenerateXBytesOfRandomEntropy(32);
                }
                myRijndael.KeySize = pO.KeySizeInBytes * 8;
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), pO.Salt,
                    pO.DerivationIterations);
                myRijndael.Key = rfc2898.GetBytes(pO.KeySizeInBytes);
            }

            byte[] utf8Text = new System.Text.UTF8Encoding().GetBytes(plainText);
            ICryptoTransform transform = myRijndael.CreateEncryptor();
            byte[] cipherText = transform.TransformFinalBlock(utf8Text, 0, utf8Text.Length);
            string cipherWithSaltAndIv;
            var cipherWithSaltAndIvObject = new CipherTextObject(pO, cipherText, myRijndael.IV);
            string json = JsonConvert.SerializeObject(cipherWithSaltAndIvObject, Formatting.None);
            return json;
        }

        public static string Decrypt(string cipherTextJson, string passPhrase)
        {
            CipherTextObject cO = JsonConvert.DeserializeObject<CipherTextObject>(cipherTextJson);

            var myRijndael = new RijndaelManaged();
            myRijndael.BlockSize = 128;
            myRijndael.KeySize = cO.KeySizeInBytes * 8;
            myRijndael.IV = Convert.FromBase64String(cO.AesRijndaelIv);
            myRijndael.Padding = PaddingMode.PKCS7;
            myRijndael.Mode = CipherMode.CBC;
            var salt = ScryptHandler.StringToByteArray(cO.Salt);
            if (cO.DerivationType == "scrypt")
            {
                myRijndael.Key =
                    ScryptHandler.GetOnlyHashBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), cO);
            }
            else
            {
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), salt,
                    cO.DerivationIterations);
                myRijndael.Key = rfc2898.GetBytes(cO.KeySizeInBytes);
            }

            var encryptedBytes = Convert.FromBase64String(cO.CipherOutputText);
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
