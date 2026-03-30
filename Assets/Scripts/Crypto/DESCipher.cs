using System;
using System.Text;

namespace Kriptoloji.Crypto
{
    /// <summary>
    /// DES (Data Encryption Standard) - Block Cipher Implementation
    /// 64-bit blok boyutu, 56-bit anahtar (64-bit girilir, 8 bit parity)
    /// 16 round Feistel yapisinda calisir.
    /// </summary>
    public static class DESCipher
    {
        #region Permutation Tables

        // Initial Permutation (IP) - 64 bit girisi yeniden siralar
        private static readonly int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        // Final Permutation (IP^-1) - IP'nin tersi
        private static readonly int[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25
        };

        // Expansion (E) - 32 bit -> 48 bit genisletme
        private static readonly int[] E = {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        };

        // P-Box Permutation - Mangler fonksiyonu icindeki permutasyon
        private static readonly int[] P = {
            16,  7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26,  5, 18, 31, 10,
             2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
        };

        // 8 adet S-Box: 6 bit giris -> 4 bit cikis (substitution)
        private static readonly int[,,] SBoxes = {
            // S1
            {
                {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
            },
            // S2
            {
                {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
            },
            // S3
            {
                {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
            },
            // S4
            {
                {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
            },
            // S5
            {
                {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
            },
            // S6
            {
                {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
            },
            // S7
            {
                {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
            },
            // S8
            {
                {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
            }
        };

        // Anahtar icin Permuted Choice 1 (PC-1): 64-bit -> 56-bit
        private static readonly int[] PC1 = {
            57, 49, 41, 33, 25, 17,  9,
             1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
        };

        // Anahtar icin Permuted Choice 2 (PC-2): 56-bit -> 48-bit
        private static readonly int[] PC2 = {
            14, 17, 11, 24,  1,  5,
             3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        // Her rounddaki sola kaydirma miktari
        private static readonly int[] LeftShifts = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
        };

        #endregion

        #region Core DES Operations

        /// <summary>
        /// Bit dizisi uzerinde permutasyon uygular.
        /// </summary>
        private static ulong Permute(ulong input, int[] table, int inputBits)
        {
            ulong output = 0;
            for (int i = 0; i < table.Length; i++)
            {
                int bitPos = table[i];
                ulong bit = (input >> (inputBits - bitPos)) & 1;
                output |= (bit << (table.Length - 1 - i));
            }
            return output;
        }

        /// <summary>
        /// 28-bit deger uzerinde sola dairesel kaydirma.
        /// </summary>
        private static uint CircularLeftShift28(uint val, int shift)
        {
            return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
        }

        /// <summary>
        /// 16 roundluk alt anahtarlari uretir (Key Schedule).
        /// </summary>
        private static ulong[] GenerateSubkeys(ulong key)
        {
            ulong[] subkeys = new ulong[16];

            // PC-1 uygulanir: 64-bit -> 56-bit
            ulong permutedKey = Permute(key, PC1, 64);

            // C ve D yarimalarina bol (28-bit)
            uint C = (uint)((permutedKey >> 28) & 0x0FFFFFFF);
            uint D = (uint)(permutedKey & 0x0FFFFFFF);

            for (int round = 0; round < 16; round++)
            {
                // Sola dairesel kaydirma
                C = CircularLeftShift28(C, LeftShifts[round]);
                D = CircularLeftShift28(D, LeftShifts[round]);

                // C ve D birlestir (56-bit)
                ulong combined = ((ulong)C << 28) | D;

                // PC-2 uygulanir: 56-bit -> 48-bit alt anahtar
                subkeys[round] = Permute(combined, PC2, 56);
            }

            return subkeys;
        }

        /// <summary>
        /// DES F fonksiyonu (Mangler): 32-bit R ve 48-bit subkey ile calisir.
        /// E genisletme -> XOR -> S-Box -> P permutasyon
        /// </summary>
        private static uint FeistelFunction(uint R, ulong subkey)
        {
            // E genisletme: 32-bit -> 48-bit
            ulong expanded = Permute(R, E, 32);

            // XOR with subkey
            ulong xored = expanded ^ subkey;

            // S-Box substitution: 48-bit -> 32-bit
            uint sboxOutput = 0;
            for (int i = 0; i < 8; i++)
            {
                int offset = (7 - i) * 6;
                int val = (int)((xored >> offset) & 0x3F);

                // Satir: bit1 ve bit6 birlestir
                int row = ((val & 0x20) >> 4) | (val & 1);
                // Sutun: bit2-5
                int col = (val >> 1) & 0x0F;

                int sboxVal = SBoxes[i, row, col];
                sboxOutput |= (uint)(sboxVal << ((7 - i) * 4));
            }

            // P permutasyon: 32-bit -> 32-bit
            uint result = (uint)Permute(sboxOutput, P, 32);
            return result;
        }

        /// <summary>
        /// Tek bir 64-bit blogu sifreler veya cozer.
        /// </summary>
        private static ulong ProcessBlock(ulong block, ulong key, bool decrypt)
        {
            ulong[] subkeys = GenerateSubkeys(key);

            // Initial Permutation (IP)
            ulong permuted = Permute(block, IP, 64);

            // L ve R yarimalarina bol (32-bit)
            uint L = (uint)((permuted >> 32) & 0xFFFFFFFF);
            uint R = (uint)(permuted & 0xFFFFFFFF);

            // 16 round Feistel
            for (int round = 0; round < 16; round++)
            {
                int keyIndex = decrypt ? (15 - round) : round;
                uint temp = R;
                R = L ^ FeistelFunction(R, subkeys[keyIndex]);
                L = temp;
            }

            // Son roundda swap YAPILMAZ (swap geri alinir)
            ulong combined = ((ulong)R << 32) | L;

            // Final Permutation (FP = IP^-1)
            ulong result = Permute(combined, FP, 64);
            return result;
        }

        #endregion

        #region Public API

        /// <summary>
        /// Byte dizisini DES ile sifreler (ECB modu, PKCS5 padding).
        /// </summary>
        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            if (key.Length != 8)
                throw new ArgumentException("DES anahtari 8 byte (64-bit) olmalidir!");

            ulong keyValue = BytesToUlong(key);

            // PKCS5 Padding
            byte[] padded = AddPadding(plaintext);

            byte[] ciphertext = new byte[padded.Length];

            // Her 8-byte (64-bit) blogu sifrele
            for (int i = 0; i < padded.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(padded, i, block, 0, 8);
                ulong blockValue = BytesToUlong(block);

                ulong encrypted = ProcessBlock(blockValue, keyValue, false);

                byte[] encBlock = UlongToBytes(encrypted);
                Array.Copy(encBlock, 0, ciphertext, i, 8);
            }

            return ciphertext;
        }

        /// <summary>
        /// DES ile sifrelenenmis byte dizisini cozer.
        /// </summary>
        public static byte[] Decrypt(byte[] ciphertext, byte[] key)
        {
            if (key.Length != 8)
                throw new ArgumentException("DES anahtari 8 byte (64-bit) olmalidir!");
            if (ciphertext.Length % 8 != 0)
                throw new ArgumentException("Sifreli metin 8-byte bloklarin kati olmalidir!");

            ulong keyValue = BytesToUlong(key);

            byte[] decrypted = new byte[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i += 8)
            {
                byte[] block = new byte[8];
                Array.Copy(ciphertext, i, block, 0, 8);
                ulong blockValue = BytesToUlong(block);

                ulong decryptedBlock = ProcessBlock(blockValue, keyValue, true);

                byte[] decBlock = UlongToBytes(decryptedBlock);
                Array.Copy(decBlock, 0, decrypted, i, 8);
            }

            return RemovePadding(decrypted);
        }

        /// <summary>
        /// String mesaji DES ile sifreler (Hex cikti).
        /// </summary>
        public static string EncryptString(string plaintext, string keyHex)
        {
            byte[] key = HexToBytes(keyHex);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = Encrypt(plaintextBytes, key);
            return BytesToHex(ciphertext);
        }

        /// <summary>
        /// Hex formatindaki DES sifreli metni cozer.
        /// </summary>
        public static string DecryptString(string ciphertextHex, string keyHex)
        {
            byte[] key = HexToBytes(keyHex);
            byte[] ciphertext = HexToBytes(ciphertextHex);
            byte[] plaintext = Decrypt(ciphertext, key);
            return Encoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Rastgele 8-byte DES anahtari uretir.
        /// </summary>
        public static string GenerateKeyHex()
        {
            byte[] key = new byte[8];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return BytesToHex(key);
        }

        #endregion

        #region Helpers

        private static byte[] AddPadding(byte[] data)
        {
            int paddingSize = 8 - (data.Length % 8);
            byte[] padded = new byte[data.Length + paddingSize];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)paddingSize;
            return padded;
        }

        private static byte[] RemovePadding(byte[] data)
        {
            int paddingSize = data[data.Length - 1];
            if (paddingSize < 1 || paddingSize > 8) return data;
            byte[] result = new byte[data.Length - paddingSize];
            Array.Copy(data, result, result.Length);
            return result;
        }

        private static ulong BytesToUlong(byte[] bytes)
        {
            ulong result = 0;
            for (int i = 0; i < 8 && i < bytes.Length; i++)
                result = (result << 8) | bytes[i];
            return result;
        }

        private static byte[] UlongToBytes(ulong val)
        {
            byte[] bytes = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                bytes[i] = (byte)(val & 0xFF);
                val >>= 8;
            }
            return bytes;
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

        #endregion
    }
}
