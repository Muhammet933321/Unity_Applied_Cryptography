using System;
using System.Text;

namespace Kriptoloji.Crypto
{
    /// <summary>
    /// AES (Advanced Encryption Standard) - Block Cipher Implementation
    /// 128-bit blok boyutu, 128/192/256-bit anahtar destegi.
    /// SubBytes, ShiftRows, MixColumns, AddRoundKey adimlariyla calisir.
    /// </summary>
    public static class AESCipher
    {
        #region AES Constants

        // S-Box: SubBytes adiminda kullanilir (byte substitution tablosu)
        private static readonly byte[] SBox = {
            0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
            0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
            0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
            0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
            0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
            0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
            0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
            0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
            0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
            0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
            0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
            0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
            0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
            0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
            0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
            0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
        };

        // Inverse S-Box: Sifre cozmede kullanilir
        private static readonly byte[] InvSBox = {
            0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
            0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
            0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
            0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
            0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
            0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
            0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
            0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
            0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
            0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
            0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
            0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
            0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
            0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
            0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
            0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
        };

        // Round sabitleri (Rcon) - Key Expansion icin
        private static readonly byte[] Rcon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        #endregion

        #region AES Core Operations

        /// <summary>
        /// SubBytes: State'in her byte'ini S-Box ile degistirir (Confusion).
        /// </summary>
        private static void SubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = SBox[state[i, j]];
        }

        private static void InvSubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = InvSBox[state[i, j]];
        }

        /// <summary>
        /// ShiftRows: Satirlari sola kaydirarak diffusion saglar.
        /// Satir 0: kaydirma yok, Satir 1: 1, Satir 2: 2, Satir 3: 3
        /// </summary>
        private static void ShiftRows(byte[,] state)
        {
            // Row 1: 1 sola
            byte temp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp;

            // Row 2: 2 sola
            byte t0 = state[2, 0], t1 = state[2, 1];
            state[2, 0] = state[2, 2];
            state[2, 1] = state[2, 3];
            state[2, 2] = t0;
            state[2, 3] = t1;

            // Row 3: 3 sola (= 1 saga)
            temp = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = state[3, 0];
            state[3, 0] = temp;
        }

        private static void InvShiftRows(byte[,] state)
        {
            // Row 1: 1 saga
            byte temp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = temp;

            // Row 2: 2 saga
            byte t0 = state[2, 0], t1 = state[2, 1];
            state[2, 0] = state[2, 2];
            state[2, 1] = state[2, 3];
            state[2, 2] = t0;
            state[2, 3] = t1;

            // Row 3: 3 saga (= 1 sola)
            temp = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = state[3, 3];
            state[3, 3] = temp;
        }

        /// <summary>
        /// GF(2^8) alaninda carpma - MixColumns icin gerekli.
        /// </summary>
        private static byte GFMul(byte a, byte b)
        {
            byte result = 0;
            byte hi;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                    result ^= a;
                hi = (byte)(a & 0x80);
                a <<= 1;
                if (hi != 0)
                    a ^= 0x1B; // AES irreducible polynomial
                b >>= 1;
            }
            return result;
        }

        /// <summary>
        /// MixColumns: Her sutunu matris carpimi ile karistirir (Diffusion).
        /// Sabit matris: [02,03,01,01; 01,02,03,01; 01,01,02,03; 03,01,01,02]
        /// </summary>
        private static void MixColumns(byte[,] state)
        {
            for (int j = 0; j < 4; j++)
            {
                byte s0 = state[0, j], s1 = state[1, j];
                byte s2 = state[2, j], s3 = state[3, j];

                state[0, j] = (byte)(GFMul(0x02, s0) ^ GFMul(0x03, s1) ^ s2 ^ s3);
                state[1, j] = (byte)(s0 ^ GFMul(0x02, s1) ^ GFMul(0x03, s2) ^ s3);
                state[2, j] = (byte)(s0 ^ s1 ^ GFMul(0x02, s2) ^ GFMul(0x03, s3));
                state[3, j] = (byte)(GFMul(0x03, s0) ^ s1 ^ s2 ^ GFMul(0x02, s3));
            }
        }

        private static void InvMixColumns(byte[,] state)
        {
            for (int j = 0; j < 4; j++)
            {
                byte s0 = state[0, j], s1 = state[1, j];
                byte s2 = state[2, j], s3 = state[3, j];

                state[0, j] = (byte)(GFMul(0x0E, s0) ^ GFMul(0x0B, s1) ^ GFMul(0x0D, s2) ^ GFMul(0x09, s3));
                state[1, j] = (byte)(GFMul(0x09, s0) ^ GFMul(0x0E, s1) ^ GFMul(0x0B, s2) ^ GFMul(0x0D, s3));
                state[2, j] = (byte)(GFMul(0x0D, s0) ^ GFMul(0x09, s1) ^ GFMul(0x0E, s2) ^ GFMul(0x0B, s3));
                state[3, j] = (byte)(GFMul(0x0B, s0) ^ GFMul(0x0D, s1) ^ GFMul(0x09, s2) ^ GFMul(0x0E, s3));
            }
        }

        /// <summary>
        /// AddRoundKey: State ile round anahtarini XOR'lar.
        /// </summary>
        private static void AddRoundKey(byte[,] state, byte[,] roundKey)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] ^= roundKey[i, j];
        }

        #endregion

        #region Key Expansion

        /// <summary>
        /// AES Key Expansion: Ana anahtardan tum round anahtarlarini uretir.
        /// AES-128: 10 round -> 11 round key (ilk XOR dahil)
        /// </summary>
        private static byte[][,] KeyExpansion(byte[] key)
        {
            int Nk = key.Length / 4; // Anahtar kelime sayisi (4=AES128, 6=AES192, 8=AES256)
            int Nr = Nk + 6;        // Round sayisi (10, 12 veya 14)
            int totalWords = 4 * (Nr + 1);

            byte[][] w = new byte[totalWords][];

            // Ilk Nk kelimeyi dogrudan anahtardan al
            for (int i = 0; i < Nk; i++)
            {
                w[i] = new byte[] { key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3] };
            }

            // Kalan kelimeleri uret
            for (int i = Nk; i < totalWords; i++)
            {
                byte[] temp = (byte[])w[i - 1].Clone();

                if (i % Nk == 0)
                {
                    // RotWord: sola 1 byte kaydirma
                    byte t = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = t;

                    // SubWord: S-Box ile degistir
                    for (int j = 0; j < 4; j++)
                        temp[j] = SBox[temp[j]];

                    // Rcon ile XOR
                    temp[0] ^= Rcon[i / Nk - 1];
                }
                else if (Nk > 6 && i % Nk == 4)
                {
                    // AES-256 icin ekstra SubWord
                    for (int j = 0; j < 4; j++)
                        temp[j] = SBox[temp[j]];
                }

                w[i] = new byte[4];
                for (int j = 0; j < 4; j++)
                    w[i][j] = (byte)(w[i - Nk][j] ^ temp[j]);
            }

            // Round key'leri 4x4 matris olarak dondur
            byte[][,] roundKeys = new byte[Nr + 1][,];
            for (int r = 0; r <= Nr; r++)
            {
                roundKeys[r] = new byte[4, 4];
                for (int j = 0; j < 4; j++)
                    for (int i = 0; i < 4; i++)
                        roundKeys[r][i, j] = w[r * 4 + j][i];
            }

            return roundKeys;
        }

        #endregion

        #region Block Processing

        /// <summary>
        /// Byte dizisini 4x4 state matrisine donusturur (sutun oncelikli).
        /// </summary>
        private static byte[,] BytesToState(byte[] block)
        {
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = block[j * 4 + i];
            return state;
        }

        private static byte[] StateToBytes(byte[,] state)
        {
            byte[] block = new byte[16];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    block[j * 4 + i] = state[i, j];
            return block;
        }

        /// <summary>
        /// Tek bir 128-bit blogu AES ile sifreler.
        /// </summary>
        private static byte[] EncryptBlock(byte[] block, byte[][,] roundKeys, int Nr)
        {
            byte[,] state = BytesToState(block);

            // Ilk AddRoundKey
            AddRoundKey(state, roundKeys[0]);

            // Round 1 ~ Nr-1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
            for (int round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, roundKeys[round]);
            }

            // Son round (MixColumns yok)
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, roundKeys[Nr]);

            return StateToBytes(state);
        }

        /// <summary>
        /// Tek bir 128-bit blogun AES sifresini cozer.
        /// </summary>
        private static byte[] DecryptBlock(byte[] block, byte[][,] roundKeys, int Nr)
        {
            byte[,] state = BytesToState(block);

            // Son round anahtariyla basla
            AddRoundKey(state, roundKeys[Nr]);

            // Ters roundlar Nr-1 ~ 1
            for (int round = Nr - 1; round >= 1; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, roundKeys[round]);
                InvMixColumns(state);
            }

            // Ilk round
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, roundKeys[0]);

            return StateToBytes(state);
        }

        #endregion

        #region Public API

        /// <summary>
        /// Byte dizisini AES ile sifreler (ECB modu, PKCS7 padding).
        /// Anahtar: 16 byte (AES-128), 24 byte (AES-192), 32 byte (AES-256)
        /// </summary>
        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            ValidateKey(key);
            int Nr = key.Length / 4 + 6;
            byte[][,] roundKeys = KeyExpansion(key);

            byte[] padded = AddPadding(plaintext);
            byte[] ciphertext = new byte[padded.Length];

            for (int i = 0; i < padded.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(padded, i, block, 0, 16);
                byte[] encrypted = EncryptBlock(block, roundKeys, Nr);
                Array.Copy(encrypted, 0, ciphertext, i, 16);
            }

            return ciphertext;
        }

        /// <summary>
        /// AES ile sifreli byte dizisini cozer.
        /// </summary>
        public static byte[] Decrypt(byte[] ciphertext, byte[] key)
        {
            ValidateKey(key);
            if (ciphertext.Length % 16 != 0)
                throw new ArgumentException("Sifreli metin 16-byte bloklarin kati olmalidir!");

            int Nr = key.Length / 4 + 6;
            byte[][,] roundKeys = KeyExpansion(key);

            byte[] decrypted = new byte[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(ciphertext, i, block, 0, 16);
                byte[] decBlock = DecryptBlock(block, roundKeys, Nr);
                Array.Copy(decBlock, 0, decrypted, i, 16);
            }

            return RemovePadding(decrypted);
        }

        /// <summary>
        /// String mesaji AES ile sifreler.
        /// keySize: 128, 192 veya 256
        /// </summary>
        public static string EncryptString(string plaintext, string keyHex)
        {
            byte[] key = HexToBytes(keyHex);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = Encrypt(plaintextBytes, key);
            return BytesToHex(ciphertext);
        }

        /// <summary>
        /// Hex formatindaki AES sifreli metni cozer.
        /// </summary>
        public static string DecryptString(string ciphertextHex, string keyHex)
        {
            byte[] key = HexToBytes(keyHex);
            byte[] ciphertext = HexToBytes(ciphertextHex);
            byte[] plaintext = Decrypt(ciphertext, key);
            return Encoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Belirtilen boyutta rastgele AES anahtari uretir.
        /// </summary>
        public static string GenerateKeyHex(int keySize = 128)
        {
            int keyBytes = keySize / 8;
            if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32)
                throw new ArgumentException("AES anahtar boyutu 128, 192 veya 256 bit olmalidir!");

            byte[] key = new byte[keyBytes];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return BytesToHex(key);
        }

        #endregion

        #region Helpers

        private static void ValidateKey(byte[] key)
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException(
                    $"AES anahtari 16, 24 veya 32 byte olmalidir! Girilen: {key.Length} byte");
        }

        private static byte[] AddPadding(byte[] data)
        {
            int paddingSize = 16 - (data.Length % 16);
            byte[] padded = new byte[data.Length + paddingSize];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)paddingSize;
            return padded;
        }

        private static byte[] RemovePadding(byte[] data)
        {
            int paddingSize = data[data.Length - 1];
            if (paddingSize < 1 || paddingSize > 16) return data;
            byte[] result = new byte[data.Length - paddingSize];
            Array.Copy(data, result, result.Length);
            return result;
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
