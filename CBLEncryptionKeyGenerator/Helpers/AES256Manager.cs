using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CBLEncryptionKeyGenerator.Helpers
{
    public class AES256Manager
    {
        public byte[] GenerateSalt()
        {
            byte[] salt = new Byte[32];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);

            return salt;
        }

        public string Encrypt(string phraseToEncrypt, string passPhrase, byte[] salt)
        {
            byte[] phraseToEncryptBytes = Encoding.UTF8.GetBytes(phraseToEncrypt);

            var aes = Aes.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(passPhrase, salt);
            aes.BlockSize = 128;
            aes.KeySize = 128;

            aes.Key = pdb.GetBytes(32);
            aes.IV = pdb.GetBytes(16);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            string base64Encryped;
            using (var memoryStream = new MemoryStream())
            {

                using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(phraseToEncryptBytes, 0, phraseToEncryptBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cryptoStream.Close();
                }

                var byteArray = memoryStream.ToArray();
                base64Encryped = Convert.ToBase64String(byteArray);
            }

            return base64Encryped;
        }

        public string Decrypt(string cipherBase64, string passPhrase, byte[] salt)
        {
            var cipher = Convert.FromBase64String(cipherBase64);


            var aes = Aes.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(passPhrase, salt);

            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Key = pdb.GetBytes(32);
            aes.IV = pdb.GetBytes(16);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        cryptoStream.Write(cipher, 0, cipher.Length);
                        cryptoStream.FlushFinalBlock();
                        cryptoStream.Close();
                    }
                    catch (CryptographicException ex)
                    {
                        throw new CryptographicException("Passphrase or SALT are incorrect");
                    }
                }

                var byteArray = memoryStream.ToArray();
                return Encoding.Default.GetString(byteArray);
            }

        }
    }
}