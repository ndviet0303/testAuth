using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using CS2PHPCryptography;
using LitJson;

namespace TestAuthLicense
{
    internal class Program
    {
        public static string StringDecrypt = string.Empty;
        static void Main(string[] args)
        {
            string Result = string.Empty;
            RSAtoPHPCryptography rsa = new RSAtoPHPCryptography();
            rsa.LoadCertificateFromString("-----BEGIN CERTIFICATE-----\r\nMIICnjCCAgegAwIBAgIUYCn+G5GayGC/Ojqgl8bYvsU3p7MwDQYJKoZIhvcNAQEF\r\nBQAwYTELMAkGA1UEBhMCdm4xCzAJBgNVBAgMAnZuMQswCQYDVQQHDAJ2bjELMAkG\r\nA1UECgwCdm4xCzAJBgNVBAsMAnZuMQswCQYDVQQDDAJ2bjERMA8GCSqGSIb3DQEJ\r\nARYCdm4wHhcNMjMwODEwMDM0MTAwWhcNMzMwODA3MDM0MTAwWjBhMQswCQYDVQQG\r\nEwJ2bjELMAkGA1UECAwCdm4xCzAJBgNVBAcMAnZuMQswCQYDVQQKDAJ2bjELMAkG\r\nA1UECwwCdm4xCzAJBgNVBAMMAnZuMREwDwYJKoZIhvcNAQkBFgJ2bjCBnzANBgkq\r\nhkiG9w0BAQEFAAOBjQAwgYkCgYEAyGdmtR4YVoyjK7a+/jUWKUXMvfiEBqsQtv2e\r\n2Kqp24v320TVlzEQfyHWkepODf3A4Tm+TemtvWpp4ci+gWhs7w0+OFGCSWSbxiPh\r\nNgqPt2u9ARIC+TqQNx9yMrwgraDE78YKM4sEISr6jpQMq4P28c0UoW7vehMSvnRv\r\nKSMWHeECAwEAAaNTMFEwHQYDVR0OBBYEFAd4PaQYN6fI/5RpeqV9Qmf8nS0kMB8G\r\nA1UdIwQYMBaAFAd4PaQYN6fI/5RpeqV9Qmf8nS0kMA8GA1UdEwEB/wQFMAMBAf8w\r\nDQYJKoZIhvcNAQEFBQADgYEAB2H0ayqrqO/BUm1ebSItY3TZoCz7zQcVV6Iv9wwg\r\n6wYg3E2ij6MnP8NcXSGumFuOuc1BtToeq61GNBze52ElqS9RjsLzveTTaBWgehx6\r\nZoJb76qL4lbc7WwxEN4+YW/2DfyvOR9j6mZs65O6mNn7vMwSe32GQXiScIaokJUm\r\nKKU=\r\n-----END CERTIFICATE-----\r\n");
            var Data = new Licenses()
            {
                License = "123",
                Type = "YC51",
                PassWord = CreateRandomKey(15),
            };
            var DataJ = JsonMapper.ToJson(Data);
            try
            {
                using (WebClient webClient = new WebClient())
                {
                    NameValueCollection nameValueCollection = new NameValueCollection();
                    nameValueCollection["data"] = rsa.Encrypt(DataJ);
                    byte[] bytes = webClient.UploadValues("http://ecommerceweb.test/api/auth", nameValueCollection);
                    Result = Encoding.UTF8.GetString(bytes);
                }
            }
            catch
            {
                Console.Write("CC");
            }
            string message = Result;
            string password = Data.PassWord;
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] key2 = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] iv = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
            string decrypted = DecryptString(message, key2, iv);
            StringDecrypt = decrypted;
            bool check = decrypted.Contains("true") && decrypted.Contains(Data.PassWord);
            Console.Write(check);
            Console.ReadLine();
        }

        static string DecryptString(string cipherText, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;
            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);
            string plainText = String.Empty;
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                cryptoStream.FlushFinalBlock();
                byte[] plainBytes = memoryStream.ToArray();
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                memoryStream.Close();
                cryptoStream.Close();
            }
            return plainText;
        }
        static string Encrypt(string toEncrypt)
        {
            string s = 403828018.ToString();
            bool flag = true;
            byte[] bytes = Encoding.UTF8.GetBytes(toEncrypt);
            byte[] key;
            if (flag)
            {
                key = new MD5CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(s));
            }
            else
            {
                key = Encoding.UTF8.GetBytes(s);
            }
            byte[] array = new TripleDESCryptoServiceProvider
            {
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            }.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
            return Convert.ToBase64String(array, 0, array.Length);
        }

        static string CreateRandomText(int length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        static string CreateRandomKey(int length)
        {
            string text = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            char[] array = new char[length];
            for (int i = 0; i < length; i++)
            {
                array[i] = text[random.Next(0, text.Length)];
            }
            return new string(array);
        }
    }
}
