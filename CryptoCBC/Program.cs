using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CryptoCBC
{
    class Program
    {
        private static readonly Encoding Encoding = Encoding.UTF8;

        static void Main(string[] args)
        {
            string encrypted = EncryptData("Some Message", "q3t6w9z$C&F)J@NcRfUjWnZr4u7x!A%D");

            Console.WriteLine(encrypted);
        }

        

        public static string EncryptData(string message, string encryptionKey)
        {
            AesManaged aes = new AesManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.ECB
            };

            aes.Key = Encoding.GetBytes(encryptionKey);
            aes.GenerateIV();

            ICryptoTransform AESEncrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] buffer = Encoding.GetBytes(message);

            var encryptedText = Convert.ToBase64String(AESEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));

            using (HMACSHA256 hmac = new HMACSHA256(Encoding.GetBytes(encryptionKey)))
            {
                var keyValues = new Dictionary<string, object>
                {
                    { "iv", Convert.ToBase64String(aes.IV) },
                    { "value", encryptedText },
                    { "mac", hmac.ComputeHash(Encoding.GetBytes(encryptedText)) },
                };

                return Convert.ToBase64String(Encoding.GetBytes(JsonSerializer.Serialize(keyValues)));
            }
        }
    }
}
