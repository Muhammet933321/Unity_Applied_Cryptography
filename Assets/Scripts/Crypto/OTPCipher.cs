using System;
using System.Text;

namespace Kriptoloji.Crypto
{
    /// <summary>
    /// One-Time Pad (OTP) - Stream Cipher Implementation
    /// Mesaj ile ayni uzunlukta rastgele anahtar kullanarak XOR islemi yapar.
    /// Shannon'in kanitladigi gibi, tek kullanimlik sifre mutlak guvenlik saglar.
    /// </summary>
    public static class OTPCipher
    {
        private static readonly System.Random _random = new System.Random();

        /// <summary>
        /// Verilen uzunlukta rastgele bir anahtar uretir.
        /// </summary>
        public static byte[] GenerateKey(int length)
        {
            byte[] key = new byte[length];
            // Kriptografik olarak guclu rastgele sayi ureteci
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        /// <summary>
        /// OTP Sifreleme: C = M XOR K
        /// </summary>
        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            if (key.Length < plaintext.Length)
                throw new ArgumentException("Anahtar, mesajdan kisa olamaz! OTP kurali: |K| >= |M|");

            byte[] ciphertext = new byte[plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++)
            {
                ciphertext[i] = (byte)(plaintext[i] ^ key[i]);
            }
            return ciphertext;
        }

        /// <summary>
        /// OTP Sifre Cozme: M = C XOR K
        /// </summary>
        public static byte[] Decrypt(byte[] ciphertext, byte[] key)
        {
            if (key.Length < ciphertext.Length)
                throw new ArgumentException("Anahtar, sifreli metinden kisa olamaz!");

            byte[] plaintext = new byte[ciphertext.Length];
            for (int i = 0; i < ciphertext.Length; i++)
            {
                plaintext[i] = (byte)(ciphertext[i] ^ key[i]);
            }
            return plaintext;
        }

        /// <summary>
        /// String mesaji sifreler, anahtar ve sifreli metin doner.
        /// Anahtar yazdirabilir ASCII karakter olarak doner.
        /// </summary>
        public static (string ciphertextHex, string textKey) EncryptString(string plaintext)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            string textKey = GenerateTextKey(plaintextBytes.Length);
            byte[] keyBytes = Encoding.UTF8.GetBytes(textKey);
            byte[] ciphertext = Encrypt(plaintextBytes, keyBytes);

            return (BytesToHex(ciphertext), textKey);
        }

        /// <summary>
        /// Hex formatindaki sifreli metni metin anahtariyla cozer.
        /// </summary>
        public static string DecryptString(string ciphertextHex, string textKey)
        {
            byte[] ciphertext = HexToBytes(ciphertextHex);
            byte[] key = Encoding.UTF8.GetBytes(textKey);
            byte[] plaintext = Decrypt(ciphertext, key);

            return Encoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Verilen metin anahtar ile string mesaji sifreler.
        /// </summary>
        public static string EncryptWithKey(string plaintext, string textKey)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] key = Encoding.UTF8.GetBytes(textKey);
            byte[] ciphertext = Encrypt(plaintextBytes, key);
            return BytesToHex(ciphertext);
        }

        /// <summary>
        /// Verilen byte uzunlugunda yazdirabilir ASCII anahtar uretir.
        /// Her karakter 33-126 araligindadir (bosluk ve kontrol karakteri yok).
        /// </summary>
        public static string GenerateTextKey(int byteLength)
        {
            byte[] randomBytes = new byte[byteLength];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            char[] chars = new char[byteLength];
            for (int i = 0; i < byteLength; i++)
            {
                chars[i] = (char)(randomBytes[i] % 94 + 33);
            }
            return new string(chars);
        }

        public static string BytesToHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.AppendFormat("{0:X2}", b);
            return sb.ToString();
        }

        public static byte[] HexToBytes(string hex)
        {
            hex = hex.Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
    }
}
