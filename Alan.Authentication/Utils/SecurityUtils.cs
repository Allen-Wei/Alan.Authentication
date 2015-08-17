using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Alan.Authentication.Utils
{
    /// <summary>
    /// 加/解密实用类
    /// </summary>
    public static class SecurityUtils
    {
        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <returns>密文字节数组</returns>
        public static byte[] AesEncrypt(string data, byte[] key)
        {
            byte[] result;

            using (SymmetricAlgorithm algorithm = new AesCryptoServiceProvider())
            {
                algorithm.Mode = CipherMode.ECB;
                algorithm.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform transform = algorithm.CreateEncryptor(key, key))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (Stream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                        {
                            using (StreamWriter writer = new StreamWriter(cs))
                            {
                                writer.Write(data);
                            }
                            result = ms.ToArray();
                        }
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="data">待解密字节数组</param>
        /// <param name="key">密钥</param>
        /// <returns>解密后的字符串</returns>
        public static string AesDecrypt(byte[] data, byte[] key)
        {
            string result;
            using (SymmetricAlgorithm algorithm = new AesCryptoServiceProvider())
            {
                algorithm.Mode = CipherMode.ECB;
                algorithm.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform transform = algorithm.CreateDecryptor(key, key))
                {
                    using (MemoryStream ms = new MemoryStream(data))
                    {
                        using (Stream cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
                        {
                            using (StreamReader reader = new StreamReader(cs))
                            {
                                result = reader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            return result;
        }

    }
}
