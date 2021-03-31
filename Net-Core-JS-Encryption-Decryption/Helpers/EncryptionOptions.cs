using System;

namespace Net_Core_JS_Encryption_Decryption.Helpers
{
    public class EncryptionOptions
    {
        public string DerivationType; // "rfc" or "scrypt"
        public byte[] Salt;
        public byte[] RijndaelIv;
        public int Cost;
        public int BlockSize;
        public int Parallel;
        public int KeySizeInBytes; // In bytes, e. g. 32
        public int DerivationIterations; // ONly for Rfc2898, not Scrypt, should be 10,000 or above

        public EncryptionOptions(string type = "scrypt", byte[] salt = null, byte[] iVRijndaelIv = null, int cost = 16384, int blockSize = 8, int parallel = 1,
            int keySizeInBytes = 32, int derivationIterations = 10000)
        {
            DerivationType = type;
            if (salt == null)
            {
                Salt = PasswordGenerator.GetRandomByteArray(32);
            }
            else
            {
                Salt = salt;
            }

            RijndaelIv = iVRijndaelIv;

            KeySizeInBytes = keySizeInBytes;

            if (type == null || type == "scrypt")
            {
                DerivationType = "scrypt";
                Cost = cost;
                BlockSize = blockSize;
                Parallel = parallel;
            }
            else //in Case of rfc2898
            {
                DerivationType = "pbkdf2";
                DerivationIterations = derivationIterations;

            }


        }




    }
}
