using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Net_Core_JS_Encryption_Decryption
{
    public class PasswordGenerator
    {
        public static string GenerateRandomPassword(int length, string charSet = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.:-_/\!§$%&(){[]}?=@+~*,;<>|", int addHyphensEveryNLetters = 0)
        {

            // @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.:-_/\!§$%&(){[]}?=@+~*,;<>|";

            //charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            var stringChars = new char[length];

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = charSet[Next(0, charSet.Length)];
            }

            var password = new String(stringChars);
            if (addHyphensEveryNLetters != 0)
            {
                password = String.Join("-", Regex.Split(password, @"(?<=\G.{" + addHyphensEveryNLetters + "})(?!$)"));
            }

            return password;
        }

        public static byte[] GetRandomByteArray(int length)
        {
            return GenerateRandomBytes(length);
        }


        // maxExclusiveValue means this value is never returned (exclusive)
        public static int Next(int minValue, int maxExclusiveValue)
        {
            if (minValue >= maxExclusiveValue)
                throw new ArgumentOutOfRangeException("minValue must be lower than maxExclusiveValue");

            long diff = (long)maxExclusiveValue - minValue;
            long upperBound = uint.MaxValue / diff * diff;

            uint ui;
            do
            {
                ui = GetRandomUInt();
            } while (ui >= upperBound);
            return (int)(minValue + (ui % diff));
        }

        private static uint GetRandomUInt()
        {
            var randomBytes = GenerateRandomBytes(sizeof(uint));
            return BitConverter.ToUInt32(randomBytes, 0);
        }

        private static byte[] GenerateRandomBytes(int bytesNumber)
        {
            var csp = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[bytesNumber];
            csp.GetBytes(buffer);
            return buffer;
        }
    }
}
