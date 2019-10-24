using System;
using System.Collections.Generic;
using System.Text;

namespace Net_Core_JS_Encryption_Decryption
{
    public class PasswordDerivationOptions
    {
        public string DerivationType; // "rfc" or "scrypt"
        public byte[] Salt;
        public int Cost;
        public int BlockSize;
        public int Parallel;
        public int KeySizeInBytes; // In bytes, e. g. 32
        public int DerivationIterations; // ONly for Rfc2898, not Scrypt, should be 10,000 or above

        public PasswordDerivationOptions(string type = "scrypt", byte[] salt = null, int cost = 16384, int blockSize = 8, int parallel = 1,
            int keySizeInBytes = 32, int derivationIterations = 10000)
        {
            if (salt == null)
            {
                Salt = PasswordGenerator.GetRandomByteArray(32);
            }

            KeySizeInBytes = keySizeInBytes;

            if (type == "scrypt")
            {
                Cost = cost;
                BlockSize = blockSize;
                Parallel = parallel;
            }
            else //in Case of rfc2898
            {
                DerivationIterations = derivationIterations;
                DerivationType = type;
            }


        }

    }
}
