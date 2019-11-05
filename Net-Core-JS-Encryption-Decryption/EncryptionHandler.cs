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
        public static string Encrypt(string plainText, string passPhrase, EncryptionOptions eO = null)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var cipherObject = BasicAesEncryption(new System.Text.UTF8Encoding().GetBytes(plainText), passPhrase, eO);

            var cipherWithSaltAndIvObject = cipherObject.ConvertToCipherTextObject();//new CipherResultText(eO, cipherObject.CipherOutput);
            string json = JsonConvert.SerializeObject(cipherWithSaltAndIvObject, Formatting.None);
            return json;
        }

        public static CipherResult EncryptToByteArray(string plainText, string passPhrase, EncryptionOptions eO = null)
        {
            var cipherObject = BasicAesEncryption(new System.Text.UTF8Encoding().GetBytes(plainText), passPhrase, eO);
            return cipherObject;
        }



        public static CipherResult BinaryEncryptWithStaticIv(byte[] fileToEncrypt, string passPhrase,
            EncryptionOptions eO = null)
        {
            var cipherObject = BasicAesEncryption(fileToEncrypt, passPhrase, eO);
            return cipherObject;
        }


        // The resulting CipherResult contains all important settings (options) and the resulting CipherText (in Byte Array)
        public static CipherResult BasicAesEncryption(byte[] bytesToEncrypt, string passPhrase, EncryptionOptions eO = null)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var myRijndael = new RijndaelManaged();
            myRijndael.BlockSize = 128;
            if (eO == null  || eO.RijndaelIv == null)
            {
                eO = new EncryptionOptions();
                myRijndael.IV = GenerateXBytesOfRandomEntropy(16); //IV must be 16 bytes / 128 bit
                eO.RijndaelIv = myRijndael.IV;
            }
            else
            {
                myRijndael.IV = eO.RijndaelIv;
            }
            
            myRijndael.Padding = PaddingMode.PKCS7;
            myRijndael.Mode = CipherMode.CBC;

            // Using Scrypt for Key Derivation
            if (eO.DerivationType == null || eO.DerivationType == "scrypt")
            {
                eO.DerivationType = "scrypt";
                myRijndael.Key =
                    ScryptHandler.GetOnlyHashBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), eO);
            }
            // Using RFC2898 for Key Derivation
            else
            {
                if (eO.Salt == null)
                {
                    eO.Salt = GenerateXBytesOfRandomEntropy(32);
                }
                myRijndael.KeySize = eO.KeySizeInBytes * 8;
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(System.Text.Encoding.UTF8.GetBytes(passPhrase), eO.Salt,
                    eO.DerivationIterations);
                myRijndael.Key = rfc2898.GetBytes(eO.KeySizeInBytes);
            }

            byte[] utf8Text = bytesToEncrypt;
            ICryptoTransform transform = myRijndael.CreateEncryptor();
            byte[] cipherText = transform.TransformFinalBlock(utf8Text, 0, utf8Text.Length);
            var cipherWithSaltAndIvObject = new CipherResult(eO, cipherText);
            return cipherWithSaltAndIvObject;
        }


        public static string Decrypt(string cipherTextJson, string passPhrase)
        {
            CipherResultText cO = JsonConvert.DeserializeObject<CipherResultText>(cipherTextJson);

            var cipherObject = cO.ConvertToCipherObject();
            var plainTextAsBytes = BasicAesDecryption(cipherObject, passPhrase);
            return System.Text.Encoding.UTF8.GetString(plainTextAsBytes);
        }

        // The CipherResult contains all important settings (options) and the resulting CipherText (in Byte Array)
        public static byte[] BasicAesDecryption(CipherResult cO, string passPhrase)
        {
            var myRijndael = new RijndaelManaged();
            myRijndael.BlockSize = 128;
            myRijndael.KeySize = cO.KeySizeInBytes * 8;
            myRijndael.IV = cO.AesRijndaelIv;
            myRijndael.Padding = PaddingMode.PKCS7;
            myRijndael.Mode = CipherMode.CBC;
            var salt = cO.Salt;
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

            var encryptedBytes = cO.CipherOutput;
            ICryptoTransform transform = myRijndael.CreateDecryptor();
            byte[] cipherText = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            return cipherText;

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
