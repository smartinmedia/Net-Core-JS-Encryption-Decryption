using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CryptSharp.Utility;
using Net_Core_JS_Encryption_Decryption.Helpers;

namespace Net_Core_JS_Encryption_Decryption
{
    public static class ScryptHandler
    {

        public static string Hash(string password)
        {
            return ScryptEncoder(password, null, 16384, 8, 1, null, 32);
        }

        public static byte[] GetOnlyHashBytes(byte[] password, EncryptionOptions sO)
        {
            var bytes = SCrypt.ComputeDerivedKey(password, sO.Salt, sO.Cost, sO.BlockSize, sO.Parallel, null, sO.KeySizeInBytes);
            //return Convert.ToBase64String(bytes);
            return bytes;

        }

        public static byte[] GetOnlyHashBytes(byte[] password, CipherResultText sO)
        {
            var bytes = SCrypt.ComputeDerivedKey(password, ScryptHandler.StringToByteArray(sO.Salt), sO.Cost, sO.BlockSize, sO.Parallel, null, sO.KeySizeInBytes);
            //return Convert.ToBase64String(bytes);
            return bytes;

        }

        public static byte[] GetOnlyHashBytes(byte[] password, CipherResult sO)
        {
            var bytes = SCrypt.ComputeDerivedKey(password, sO.Salt, sO.Cost, sO.BlockSize, sO.Parallel, null, sO.KeySizeInBytes);
            //return Convert.ToBase64String(bytes);
            return bytes;

        }


        public static byte[] GetOnlyHashBytes(byte[] password, byte[] salt = null, int cost = 16384, int blockSize = 8, int parallel = 1,
            int? maxThreads = null, int derivedKeyLength = 32)
        {
            if (salt == null)
            {
                salt = PasswordGenerator.GetRandomByteArray(32);
            }
            var bytes = SCrypt.ComputeDerivedKey(password, salt, cost, blockSize, parallel, maxThreads, derivedKeyLength);
            //return Convert.ToBase64String(bytes);
            return bytes;

        }

        public static string GetOnlyScryptSettingsAsString(EncryptionOptions eO)
        {
            string salt = String.Empty;
            if (eO.Salt == null)
            {
                salt = "0";
            }
            else
            {
                salt = ByteArrayToString(eO.Salt);
            }

            return "scrypt2:" + eO.Cost.ToString() + ":" + eO.BlockSize.ToString() + ":" + eO.Parallel.ToString() + ":" + "0:" + eO.KeySizeInBytes.ToString()
                   + ":" + salt + ":0";

        }

        public static EncryptionOptions GetEncryptionOptionsFromScryptSettings(string settings)
        {
            var eO = new EncryptionOptions();

            var scryptArray = settings.Split(":");
            if (scryptArray.Length < 8)
            {
                return null;
            }
            if (scryptArray[0] != "scrypt2")
            {
                return null;
            }

            eO.Salt = StringToByteArray(scryptArray[6]);
            eO.Cost = Convert.ToInt32(scryptArray[1]);
            eO.BlockSize = Convert.ToInt32(scryptArray[2]);
            eO.Parallel = Convert.ToInt32(scryptArray[3]);
            eO.KeySizeInBytes = Convert.ToInt32(scryptArray[5]);
            return eO;
        }



        public static string Hash(string password, string salt)
        {
            return ScryptEncoder(password, salt, 16384, 8, 1, null, 32);

        }

        public static string Hash(string password, string salt, int cost = 16384, int blockSize = 8, int parallel = 1,
            int? maxThreads = null, int derivedKeyLength = 32)
        {
            return ScryptEncoder(password, salt, cost, blockSize, parallel, maxThreads, derivedKeyLength);
        }

        
        public static bool ComparePasswordWithHash(string password, string scryptHashString)
        {
            var scryptArray = scryptHashString.Split(":");
            if (scryptArray.Length < 8)
            {
                return false;
            }
            if (scryptArray[0] != "scrypt2")
            {
                return false;
            }

            var saltBytes = StringToByteArray(scryptArray[6]);
            var hashBytes = StringToByteArray(scryptArray[7]);
            int cost = Convert.ToInt32(scryptArray[1]);
            int blockSize = Convert.ToInt32(scryptArray[2]);
            int parallel = Convert.ToInt32(scryptArray[3]);
            int? maxThreads = Convert.ToInt32(scryptArray[4]);
            int derivedKeyLength = Convert.ToInt32(scryptArray[5]);
            if (maxThreads == 0)
            {
                maxThreads = null;
            }

            var result = SCrypt.ComputeDerivedKey(Encoding.UTF8.GetBytes(password), saltBytes, cost, blockSize, parallel, maxThreads, derivedKeyLength);
            if (ByteArrayToString(result) == scryptArray[7])
            {
                return true;
            }

            return false;
        }

       private static string ScryptEncoder(string secret, string salt, int cost = 16384, int blockSize = 8, int parallel = 1, int? maxThreads = null, int derivedKeyLengthInBytes = 32)
        {
            var keyBytes = Encoding.UTF8.GetBytes(secret);
            byte[] saltBytes;
            if (string.IsNullOrEmpty(salt))
            {
                saltBytes = PasswordGenerator.GetRandomByteArray(32);
            }
            else
            {
                saltBytes = Encoding.UTF8.GetBytes(salt);
            }

            var bytes = SCrypt.ComputeDerivedKey(keyBytes, saltBytes, cost, blockSize, parallel, maxThreads, derivedKeyLengthInBytes);
            //return Convert.ToBase64String(bytes);

            string maxThreadsString;
            if (maxThreads == null)
            {
                maxThreadsString = "0";
            }
            else
            {
                maxThreadsString = maxThreads.ToString();

            }

            string hash = "scrypt2:" + cost.ToString() + ":" + blockSize.ToString() + ":" + parallel.ToString() + ":" + maxThreadsString + ":" + derivedKeyLengthInBytes.ToString()
                          + ":" + ByteArrayToString(saltBytes) + ":" + ByteArrayToString(bytes);

            return hash;
        }



        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

    }
}
