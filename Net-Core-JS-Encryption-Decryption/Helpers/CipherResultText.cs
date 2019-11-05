using System;
using System.Collections.Generic;
using System.Text;

namespace Net_Core_JS_Encryption_Decryption.Helpers
{
    public class CipherResultText
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


        public CipherResultText()
        {

        }

        public CipherResultText(EncryptionOptions eO, byte[] cipherText)
        {
            if (eO != null)
            {
                DerivationType = eO.DerivationType;
                Salt = ScryptHandler.ByteArrayToString(eO.Salt);
                Cost = eO.Cost;
                BlockSize = eO.BlockSize;
                Parallel = eO.Parallel;
                KeySizeInBytes = eO.KeySizeInBytes;
                DerivationIterations = eO.DerivationIterations;
                CipherOutputText = Convert.ToBase64String(cipherText);
                AesRijndaelIv = Convert.ToBase64String(eO.RijndaelIv);
            }

        }

        public CipherResult ConvertToCipherObject()
        {
            var cipherObject = new CipherResult()
            {
                AesRijndaelIv = Convert.FromBase64String(AesRijndaelIv),
                BlockSize = BlockSize,
                CipherOutput = Convert.FromBase64String(CipherOutputText),
                Cost = Cost,
                DerivationIterations = DerivationIterations,
                DerivationType = DerivationType,
                KeySizeInBytes = KeySizeInBytes,
                Parallel = Parallel,
                Salt = ScryptHandler.StringToByteArray(Salt)
            };
            return cipherObject;

        }
    }
}
