using System;
using System.Collections.Generic;
using System.Text;

namespace Net_Core_JS_Encryption_Decryption.Helpers
{
    public class CipherResult
    {
        public string DerivationType { get; set; } // "rfc2898" or "scrypt"
        public byte[] Salt { get; set; } // In HEX string
        public int Cost { get; set; }
        public int BlockSize { get; set; }
        public int Parallel { get; set; }
        public int KeySizeInBytes { get; set; } // In bytes, e. g. 32
        public int DerivationIterations { get; set; } // ONly for Rfc2898, not Scrypt, should be 10,000 or above
        public byte[] AesRijndaelIv { get; set; }
        public byte[] CipherOutput { get; set; }

        public CipherResult()
        {


        }
        public CipherResult(EncryptionOptions eO, byte[] cipherText)
        {
            if (eO != null)
            {
                DerivationType = eO.DerivationType;
                Salt = eO.Salt;
                Cost = eO.Cost;
                BlockSize = eO.BlockSize;
                Parallel = eO.Parallel;
                KeySizeInBytes = eO.KeySizeInBytes;
                DerivationIterations = eO.DerivationIterations;
                CipherOutput = cipherText;
                AesRijndaelIv = eO.RijndaelIv;
            }

        }

        public CipherResultText ConvertToCipherTextObject()
        {
            var cipherTextObject = new CipherResultText()
            {
                AesRijndaelIv = Convert.ToBase64String(AesRijndaelIv),
                BlockSize = BlockSize,
                CipherOutputText = (CipherOutput == null) ? null : Convert.ToBase64String(CipherOutput),
                Cost = Cost,
                DerivationIterations = DerivationIterations,
                DerivationType = DerivationType,
                KeySizeInBytes = KeySizeInBytes,
                Parallel = Parallel,
                Salt = ScryptHandler.ByteArrayToString(Salt)
            };
            return cipherTextObject;

        }
    }
}
