using System;
using System.Collections.Generic;
using System.Text;

namespace Net_Core_JS_Encryption_Decryption.Helpers
{
    public class CipherTextObject
    {
        public string DerivationType { get; set; } // "rfc2898" or "scrypt"
        public string Salt { get; set; } // In HEX string
        public int Cost { get; set; }
        public int BlockSize { get; set; }
        public int Parallel { get; set; }
        public int KeySizeInBytes { get; set; } // In bytes, e. g. 32
        public int DerivationIterations { get; set; } // ONly for Rfc2898, not Scrypt, should be 10,000 or above
        public string AesRijndaelIv { get; set; } // In base64
        public string CipherOutputText { get; set; } // In base64

        public CipherTextObject(PasswordDerivationOptions pO, byte[] cipherText, byte[] rijndaelIv)
        {
            if (pO != null)
            {
                DerivationType = pO.DerivationType;
                Salt = ScryptHandler.ByteArrayToString(pO.Salt);
                Cost = pO.Cost;
                BlockSize = pO.BlockSize;
                Parallel = pO.Parallel;
                KeySizeInBytes = pO.KeySizeInBytes;
                DerivationIterations = pO.DerivationIterations;
                CipherOutputText = Convert.ToBase64String(cipherText);
                AesRijndaelIv = Convert.ToBase64String(rijndaelIv);
            }

        }
    }
}
