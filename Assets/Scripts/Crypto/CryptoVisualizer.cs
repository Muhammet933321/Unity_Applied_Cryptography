using System;
using System.Collections.Generic;
using System.Text;

namespace Kriptoloji.Crypto
{
    /// <summary>
    /// Her sifreleme algoritmasinin adim adim calismasini
    /// metin olarak gorsellestirir. Egitim amacli.
    /// </summary>
    public static class CryptoVisualizer
    {
        // ==================== OTP Gorsellestirme ====================

        public static List<string> VisualizeOTPEncrypt(byte[] ptBytes, byte[] keyBytes, OutputFormat fmt)
        {
            var steps = new List<string>();
            OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
            string fmtLabel = GetFormatLabel(fmt);
            string cipherFmtLabel = GetFormatLabel(cipherFmt);

            if (keyBytes == null || keyBytes.Length == 0)
            {
                keyBytes = new byte[ptBytes.Length];
                new System.Random().NextBytes(keyBytes);
            }

            steps.Add("<color=#4DC8FF><b>===  OTP (One-Time Pad) SIFRELEME  ===</b></color>");
            steps.Add("");
            steps.Add("<color=#CCB833>Kural:  C = M XOR K  (her byte birebir XOR'lanir)</color>");
            steps.Add("");

            // Veri
            steps.Add($"<color=#88CC88>[Adim 1]</color> Veri ({fmtLabel} formatinda):");
            steps.Add("  " + CryptoFormatter.BytesToFormat(ptBytes, fmt));
            steps.Add($"  Uzunluk: {ptBytes.Length} byte");
            steps.Add("");

            // Anahtar
            steps.Add($"<color=#88CC88>[Adim 2]</color> Anahtar ({fmtLabel} formatinda, ayni uzunlukta):");
            steps.Add("  K = " + CryptoFormatter.BytesToFormat(keyBytes, fmt));
            steps.Add($"  Byte uzunlugu:  |M| = {ptBytes.Length}  |  |K| = {keyBytes.Length}");
            steps.Add("");

            // XOR islemleri
            steps.Add("<color=#88CC88>[Adim 3]</color> Byte byte XOR islemi:");
            byte[] cipher = new byte[ptBytes.Length];
            int showCount = Math.Min(ptBytes.Length, 6);
            for (int i = 0; i < showCount; i++)
            {
                cipher[i] = (byte)(ptBytes[i] ^ keyBytes[i]);
                string line = $"  Byte {i}: {FormatSingleByte(ptBytes[i], fmt)} XOR {FormatSingleByte(keyBytes[i], fmt)} = <color=#FFAA44>{FormatSingleByte(cipher[i], fmt)}</color>";
                if (fmt != OutputFormat.Binary)
                    line += $"    ({Convert.ToString(ptBytes[i], 2).PadLeft(8, '0')} XOR {Convert.ToString(keyBytes[i], 2).PadLeft(8, '0')} = {Convert.ToString(cipher[i], 2).PadLeft(8, '0')})";
                steps.Add(line);
            }
            for (int i = showCount; i < ptBytes.Length; i++)
                cipher[i] = (byte)(ptBytes[i] ^ keyBytes[i]);

            if (ptBytes.Length > showCount)
                steps.Add($"  ... ({ptBytes.Length - showCount} byte daha)");
            steps.Add("");

            // Sonuc
            steps.Add($"<color=#88CC88>[Sonuc]</color> Sifreli veri ({cipherFmtLabel}):");
            steps.Add("  C = " + CryptoFormatter.BytesToFormat(cipher, cipherFmt));
            steps.Add("");
            steps.Add("<color=#999999>NOT: Anahtar yalnizca 1 kez kullanilmalidir!</color>");
            steps.Add("<color=#999999>Ayni anahtarla 2 mesaj sifrelenmesi guvenilmezdir.</color>");

            return steps;
        }

        // ==================== DES Gorsellestirme ====================

        public static List<string> VisualizeDESEncrypt(byte[] ptBytes, byte[] key, OutputFormat fmt)
        {
            var steps = new List<string>();
            OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
            string fmtLabel = GetFormatLabel(fmt);
            string cipherFmtLabel = GetFormatLabel(cipherFmt);

            steps.Add("<color=#4DC8FF><b>===  DES SIFRELEME ADIMLARI  ===</b></color>");
            steps.Add("");
            steps.Add("<color=#CCB833>Yapi: 16-round Feistel Network</color>");
            steps.Add("<color=#CCB833>Blok: 64-bit | Anahtar: 56-bit (64-bit girilir)</color>");
            steps.Add("");

            // Girdi
            steps.Add($"<color=#88CC88>[Girdi]</color> Veri ({fmtLabel} formatinda):");
            steps.Add("  " + CryptoFormatter.BytesToFormat(ptBytes, fmt));
            steps.Add($"  Uzunluk: {ptBytes.Length} byte");
            steps.Add("");

            // Padding
            int paddingSize = 8 - (ptBytes.Length % 8);
            steps.Add("<color=#88CC88>[Adim 1]</color> PKCS5 Padding eklenir:");
            steps.Add($"  Orijinal: {ptBytes.Length} byte");
            steps.Add($"  Padding:  {paddingSize} byte (0x{paddingSize:X2} eklenir)");
            steps.Add($"  Toplam:   {ptBytes.Length + paddingSize} byte = {(ptBytes.Length + paddingSize) / 8} blok x 64-bit");
            steps.Add("");

            // Ilk blogu goster (detayli)
            byte[] firstBlock = new byte[8];
            Array.Copy(ptBytes, 0, firstBlock, 0, Math.Min(8, ptBytes.Length));
            if (ptBytes.Length < 8)
            {
                for (int i = ptBytes.Length; i < 8; i++)
                    firstBlock[i] = (byte)paddingSize;
            }

            steps.Add("<color=#88CC88>[Adim 2]</color> Ilk 64-bit blok (ornek):");
            steps.Add("  Blok = " + FormatBytes(firstBlock));
            steps.Add("");

            // Key Schedule
            steps.Add("<color=#88CC88>[Adim 3]</color> Anahtar Cizelgesi (Key Schedule):");
            steps.Add("  Ana Anahtar: " + FormatBytes(key));
            steps.Add("  PC-1 uygulanir: 64-bit -> 56-bit (parity bitleri atilir)");
            steps.Add("  C0 ve D0 yarimlarinina bolunur (28-bit + 28-bit)");
            steps.Add("  Her roundda sola dairesel kaydirma + PC-2 ile 48-bit alt anahtar uretilir");
            steps.Add("  Toplam: 16 alt anahtar (K1...K16)");
            steps.Add("");

            // Feistel Rounds
            steps.Add("<color=#88CC88>[Adim 4]</color> Initial Permutation (IP):");
            steps.Add("  64-bit girisi IP tablosuna gore yeniden siralar");
            steps.Add("  L0 (sol 32-bit) ve R0 (sag 32-bit) alinir");
            steps.Add("");

            steps.Add("<color=#88CC88>[Adim 5]</color> 16 Round Feistel Yapisinda:");
            steps.Add("  <color=#CCB833>Her round icin:</color>");
            steps.Add("    Li = R(i-1)");
            steps.Add("    Ri = L(i-1) XOR F(R(i-1), Ki)");
            steps.Add("");
            steps.Add("  <color=#CCB833>F Fonksiyonu (Mangler):</color>");
            steps.Add("    1. E-Genisletme:  R (32-bit) -> 48-bit");
            steps.Add("    2. XOR:           E(R) XOR Ki (48-bit)");
            steps.Add("    3. S-Box:         48-bit -> 32-bit (8 adet S-Box, 6->4 bit)");
            steps.Add("    4. P-Permutasyon: 32-bit yeniden siralama");
            steps.Add("");

            // Ilk birka round icin L,R degerlerini hesapla
            ulong blockVal = BytesToUlong(firstBlock);
            ulong keyVal = BytesToUlong(key);
            ulong permuted = SimplePermute(blockVal, GetIP(), 64);
            uint L = (uint)((permuted >> 32) & 0xFFFFFFFF);
            uint R = (uint)(permuted & 0xFFFFFFFF);

            steps.Add("  <color=#AAAAAA>Round  |  L (Hex)    |  R (Hex)</color>");
            steps.Add($"  <color=#AAAAAA>  0    |  {L:X8}  |  {R:X8}</color>");

            // 16 round (sadece sonuclari goster)
            ulong[] subkeys = SimpleGenerateSubkeys(keyVal);
            for (int round = 0; round < 16; round++)
            {
                uint temp = R;
                R = L ^ SimpleFeistel(R, subkeys[round]);
                L = temp;
                if (round < 3 || round == 15)
                    steps.Add($"  <color=#AAAAAA>  {round + 1,2}   |  {L:X8}  |  {R:X8}</color>");
                else if (round == 3)
                    steps.Add("  <color=#AAAAAA>  ...  (round 4-15 atlanir)  ...</color>");
            }
            steps.Add("");

            steps.Add("<color=#88CC88>[Adim 6]</color> Final Permutation (IP^-1):");
            steps.Add("  R16 + L16 birlestirilir (32+32 = 64-bit)");
            steps.Add("  FP tablosuyla ters permutasyon uygulanir");
            steps.Add("");

            // Gercek sonuc
            byte[] cipherAll = DESCipher.Encrypt(ptBytes, key);
            steps.Add($"<color=#88CC88>[Sonuc]</color> Sifreli veri ({cipherFmtLabel}):");
            steps.Add("  " + CryptoFormatter.BytesToFormat(cipherAll, cipherFmt));

            return steps;
        }

        // ==================== AES Gorsellestirme ====================

        public static List<string> VisualizeAESEncrypt(byte[] ptBytes, byte[] key, OutputFormat fmt)
        {
            var steps = new List<string>();
            OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
            string fmtLabel = GetFormatLabel(fmt);
            string cipherFmtLabel = GetFormatLabel(cipherFmt);
            int Nk = key.Length / 4;
            int Nr = Nk + 6;

            steps.Add("<color=#4DC8FF><b>===  AES SIFRELEME ADIMLARI  ===</b></color>");
            steps.Add("");
            steps.Add($"<color=#CCB833>Mod: AES-{key.Length * 8} | Blok: 128-bit | Round: {Nr}</color>");
            steps.Add("");

            // Girdi
            steps.Add($"<color=#88CC88>[Girdi]</color> Veri ({fmtLabel} formatinda):");
            steps.Add("  " + CryptoFormatter.BytesToFormat(ptBytes, fmt));
            steps.Add($"  Uzunluk: {ptBytes.Length} byte");
            steps.Add("");

            // Padding
            int paddingSize = 16 - (ptBytes.Length % 16);
            steps.Add("<color=#88CC88>[Adim 1]</color> PKCS7 Padding:");
            steps.Add($"  Orijinal: {ptBytes.Length} byte");
            steps.Add($"  Padding:  {paddingSize} byte (0x{paddingSize:X2})");
            steps.Add($"  Toplam:   {ptBytes.Length + paddingSize} byte = {(ptBytes.Length + paddingSize) / 16} blok x 128-bit");
            steps.Add("");

            // Ilk blogu al
            byte[] firstBlock = new byte[16];
            Array.Copy(ptBytes, 0, firstBlock, 0, Math.Min(16, ptBytes.Length));
            if (ptBytes.Length < 16)
            {
                for (int i = ptBytes.Length; i < 16; i++)
                    firstBlock[i] = (byte)paddingSize;
            }

            // State matrisi
            steps.Add("<color=#88CC88>[Adim 2]</color> Ilk blok -> 4x4 State Matrisi (sutun oncelikli):");
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = firstBlock[j * 4 + i];
            steps.Add(FormatState(state));
            steps.Add("");

            // Key Expansion
            steps.Add("<color=#88CC88>[Adim 3]</color> Key Expansion:");
            steps.Add($"  Ana Anahtar ({key.Length} byte): {FormatBytes(key)}");
            steps.Add($"  {Nr + 1} round key uretilir (her biri 4x4 = 16 byte)");
            steps.Add("  Her kelime icin: RotWord -> SubWord -> XOR Rcon -> XOR W[i-Nk]");
            steps.Add("");

            // Round 0: AddRoundKey
            steps.Add("<color=#88CC88>[Adim 4]</color> Ilk AddRoundKey (Round 0):");
            steps.Add("  State XOR RoundKey[0]");

            byte[,] roundKey0 = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    roundKey0[i, j] = key[j * 4 + i];

            // XOR uygula
            byte[,] afterRK0 = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    afterRK0[i, j] = (byte)(state[i, j] ^ roundKey0[i, j]);

            steps.Add("  State sonrasi:");
            steps.Add(FormatState(afterRK0));
            steps.Add("");

            // Round 1 detayli
            steps.Add($"<color=#88CC88>[Adim 5]</color> Round 1 ~ {Nr - 1} (her roundda 4 islem):");
            steps.Add("");
            steps.Add("  <color=#FFAA44>a) SubBytes</color> - Her byte S-Box ile degistirilir (Confusion)");
            steps.Add("     Ornek: " + $"{afterRK0[0, 0]:X2} -> S-Box[{afterRK0[0, 0] >> 4:X},{afterRK0[0, 0] & 0xF:X}] = {GetSBox(afterRK0[0, 0]):X2}");
            steps.Add("");
            steps.Add("  <color=#FFAA44>b) ShiftRows</color> - Satirlar sola kaydrilir (Diffusion)");
            steps.Add("     Satir 0: kaydirma yok");
            steps.Add("     Satir 1: 1 byte sola");
            steps.Add("     Satir 2: 2 byte sola");
            steps.Add("     Satir 3: 3 byte sola");
            steps.Add("");
            steps.Add("  <color=#FFAA44>c) MixColumns</color> - Her sutun GF(2^8) matris carpimiyla karisir");
            steps.Add("     Matris: [02 03 01 01]");
            steps.Add("             [01 02 03 01]");
            steps.Add("             [01 01 02 03]");
            steps.Add("             [03 01 01 02]");
            steps.Add("");
            steps.Add("  <color=#FFAA44>d) AddRoundKey</color> - State XOR RoundKey[r]");
            steps.Add("");

            steps.Add($"<color=#88CC88>[Adim 6]</color> Son Round ({Nr}):");
            steps.Add("  SubBytes -> ShiftRows -> AddRoundKey");
            steps.Add("  (MixColumns YAPILMAZ - son roundda atlanir)");
            steps.Add("");

            // Sonuc
            byte[] cipherAll = AESCipher.Encrypt(ptBytes, key);
            steps.Add($"<color=#88CC88>[Sonuc]</color> Sifreli veri ({cipherFmtLabel}):");
            steps.Add("  " + CryptoFormatter.BytesToFormat(cipherAll, cipherFmt));

            return steps;
        }

        // ==================== Yardimci Metodlar ====================

        private static string GetFormatLabel(OutputFormat fmt)
        {
            switch (fmt)
            {
                case OutputFormat.Hex: return "Hex";
                case OutputFormat.Binary: return "Binary";
                case OutputFormat.Decimal: return "Decimal";
                case OutputFormat.Base64: return "Base64";
                case OutputFormat.Text: return "Metin (UTF-8)";
                default: return "Hex";
            }
        }

        private static string FormatSingleByte(byte b, OutputFormat fmt)
        {
            switch (fmt)
            {
                case OutputFormat.Binary:
                    return Convert.ToString(b, 2).PadLeft(8, '0');
                case OutputFormat.Decimal:
                    return b.ToString();
                case OutputFormat.Hex:
                default:
                    return b.ToString("X2");
            }
        }

        private static string FormatBytes(byte[] bytes)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i > 0) sb.Append(" ");
                sb.AppendFormat("{0:X2}", bytes[i]);
            }
            return sb.ToString();
        }

        private static string FormatState(byte[,] state)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                sb.Append("    | ");
                for (int j = 0; j < 4; j++)
                {
                    if (j > 0) sb.Append("  ");
                    sb.AppendFormat("{0:X2}", state[i, j]);
                }
                sb.Append(" |");
                if (i < 3) sb.AppendLine();
            }
            return sb.ToString();
        }

        // AES S-Box lookup
        private static readonly byte[] SBoxTable = {
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

        private static byte GetSBox(byte input) => SBoxTable[input];

        // ===== DES icin basitlesilmis hesaplama metotlari =====

        private static readonly int[] IPTable = {
            58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
        };

        private static readonly int[] ETable = {
            32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
            12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
            24,25,26,27,28,29, 28,29,30,31,32,1
        };

        private static readonly int[] PTable = {
            16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25
        };

        private static readonly int[] PC1Table = {
            57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
            10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
            63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
            14,6,61,53,45,37,29, 21,13,5,28,20,12,4
        };

        private static readonly int[] PC2Table = {
            14,17,11,24,1,5, 3,28,15,6,21,10,
            23,19,12,4,26,8, 16,7,27,20,13,2,
            41,52,31,37,47,55, 30,40,51,45,33,48,
            44,49,39,56,34,53, 46,42,50,36,29,32
        };

        private static readonly int[] LeftShifts = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

        private static readonly int[,,] DesSBoxes = {
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };

        private static int[] GetIP() => IPTable;

        private static ulong SimplePermute(ulong input, int[] table, int inputBits)
        {
            ulong output = 0;
            for (int i = 0; i < table.Length; i++)
            {
                ulong bit = (input >> (inputBits - table[i])) & 1;
                output |= (bit << (table.Length - 1 - i));
            }
            return output;
        }

        private static uint SimpleCircularLeft28(uint val, int shift)
        {
            return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
        }

        private static ulong[] SimpleGenerateSubkeys(ulong key)
        {
            ulong[] subkeys = new ulong[16];
            ulong permutedKey = SimplePermute(key, PC1Table, 64);
            uint C = (uint)((permutedKey >> 28) & 0x0FFFFFFF);
            uint D = (uint)(permutedKey & 0x0FFFFFFF);

            for (int round = 0; round < 16; round++)
            {
                C = SimpleCircularLeft28(C, LeftShifts[round]);
                D = SimpleCircularLeft28(D, LeftShifts[round]);
                ulong combined = ((ulong)C << 28) | D;
                subkeys[round] = SimplePermute(combined, PC2Table, 56);
            }
            return subkeys;
        }

        private static uint SimpleFeistel(uint R, ulong subkey)
        {
            ulong expanded = SimplePermute(R, ETable, 32);
            ulong xored = expanded ^ subkey;
            uint sboxOutput = 0;
            for (int i = 0; i < 8; i++)
            {
                int offset = (7 - i) * 6;
                int val = (int)((xored >> offset) & 0x3F);
                int row = ((val & 0x20) >> 4) | (val & 1);
                int col = (val >> 1) & 0x0F;
                int sboxVal = DesSBoxes[i, row, col];
                sboxOutput |= (uint)(sboxVal << ((7 - i) * 4));
            }
            return (uint)SimplePermute(sboxOutput, PTable, 32);
        }

        private static ulong BytesToUlong(byte[] bytes)
        {
            ulong result = 0;
            for (int i = 0; i < 8 && i < bytes.Length; i++)
                result = (result << 8) | bytes[i];
            return result;
        }
    }
}
