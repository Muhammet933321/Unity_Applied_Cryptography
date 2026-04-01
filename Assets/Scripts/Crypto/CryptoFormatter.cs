using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Kriptoloji.Crypto
{
    public enum OutputFormat
    {
        Hex,        // 16'lik taban (varsayilan)
        Binary,     // 2'lik taban
        Decimal,    // 10'luk taban
        Base64,     // Base64 kodlama
        Text,       // UTF-8 metin (ham)
        ASCII       // ASCII metin (7-bit, 1 byte/karakter)
    }

    public static class CryptoFormatter
    {
        public static readonly string[] FormatLabels = {
            "Hex (Taban 16)",
            "Binary (Taban 2)",
            "Decimal (Taban 10)",
            "Base64",
            "Metin (UTF-8)",
            "ASCII"
        };

        public static OutputFormat FromIndex(int index)
        {
            switch (index)
            {
                case 0: return OutputFormat.Hex;
                case 1: return OutputFormat.Binary;
                case 2: return OutputFormat.Decimal;
                case 3: return OutputFormat.Base64;
                case 4: return OutputFormat.Text;
                case 5: return OutputFormat.ASCII;
                default: return OutputFormat.Hex;
            }
        }

        /// <summary>
        /// Byte dizisini secilen formata donusturur.
        /// </summary>
        public static string BytesToFormat(byte[] data, OutputFormat format)
        {
            switch (format)
            {
                case OutputFormat.Hex:
                    return BytesToHex(data);

                case OutputFormat.Binary:
                    return BytesToBinary(data);

                case OutputFormat.Decimal:
                    return BytesToDecimal(data);

                case OutputFormat.Base64:
                    return Convert.ToBase64String(data);

                case OutputFormat.Text:
                    return Encoding.UTF8.GetString(data);

                case OutputFormat.ASCII:
                    return Encoding.ASCII.GetString(data);

                default:
                    return BytesToHex(data);
            }
        }

        /// <summary>
        /// Secilen formattaki stringi byte dizisine geri donusturur.
        /// </summary>
        public static byte[] FormatToBytes(string input, OutputFormat format)
        {
            input = input.Trim();
            switch (format)
            {
                case OutputFormat.Hex:
                    return HexToBytes(input);

                case OutputFormat.Binary:
                    return BinaryToBytes(input);

                case OutputFormat.Decimal:
                    return DecimalToBytes(input);

                case OutputFormat.Base64:
                    return Base64ToBytes(input);

                case OutputFormat.Text:
                    return Encoding.UTF8.GetBytes(input);

                case OutputFormat.ASCII:
                    foreach (char c in input)
                        if (c > 127)
                            throw new FormatException($"ASCII desteklenmeyen karakter: '{c}' (kod: {(int)c}). ASCII yalnizca 0-127 arasi karakterleri destekler.");
                    return Encoding.ASCII.GetBytes(input);

                default:
                    return HexToBytes(input);
            }
        }

        /// <summary>
        /// Girdi stringindeki gecersiz karakterleri format kuralina gore temizler.
        /// </summary>
        public static string SanitizeInput(string value, OutputFormat format)
        {
            if (string.IsNullOrEmpty(value)) return value;

            switch (format)
            {
                case OutputFormat.Hex:
                    return Regex.Replace(value, @"[^0-9A-Fa-f\s]", "");

                case OutputFormat.Binary:
                    return Regex.Replace(value, @"[^01\s]", "");

                case OutputFormat.Decimal:
                    return Regex.Replace(value, @"[^0-9\s]", "");

                case OutputFormat.Base64:
                    return Regex.Replace(value, @"[^A-Za-z0-9+/=\s]", "");

                case OutputFormat.Text:
                    return value;

                case OutputFormat.ASCII:
                    return Regex.Replace(value, @"[^\x00-\x7F]", "");

                default:
                    return value;
            }
        }

        /// <summary>
        /// Sifreli veri icin guvenli format belirler.
        /// Text modda sifreli veri UTF-8 olarak gosterilemez, Hex'e duser.
        /// </summary>
        public static OutputFormat GetCipherFormat(OutputFormat format)
        {
            return (format == OutputFormat.Text || format == OutputFormat.ASCII) ? OutputFormat.Hex : format;
        }

        /// <summary>
        /// Girdi stringinin gercek bit uzunlugunu hesaplar.
        /// Binary: karakter sayisi (0/1), Hex: hex digit * 4,
        /// Decimal/Base64/Text: byte sayisi * 8.
        /// </summary>
        public static int GetBitCount(string input, OutputFormat format)
        {
            if (string.IsNullOrEmpty(input)) return 0;
            input = input.Trim();

            switch (format)
            {
                case OutputFormat.Binary:
                    // Her '0' veya '1' karakteri 1 bit
                    int bits = 0;
                    foreach (char c in input)
                        if (c == '0' || c == '1') bits++;
                    return bits;

                case OutputFormat.Hex:
                    // Her hex digit 4 bit
                    int hexDigits = 0;
                    foreach (char c in input)
                        if (Uri.IsHexDigit(c)) hexDigits++;
                    return hexDigits * 4;

                case OutputFormat.Decimal:
                    return FormatToBytes(input, format).Length * 8;

                case OutputFormat.Base64:
                    return FormatToBytes(input, format).Length * 8;

                case OutputFormat.Text:
                    return Encoding.UTF8.GetBytes(input).Length * 8;

                case OutputFormat.ASCII:
                    // ASCII: her karakter tam 1 byte = 8 bit
                    return input.Length * 8;

                default:
                    return FormatToBytes(input, format).Length * 8;
            }
        }

        // ---- Hex ----
        private static string BytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.AppendFormat("{0:X2}", b);
            return sb.ToString();
        }

        private static byte[] HexToBytes(string hex)
        {
            hex = hex.Replace(" ", "");
            if (hex.Length % 2 != 0)
                hex = "0" + hex;
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        // ---- Binary ----
        private static string BytesToBinary(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 9);
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(Convert.ToString(bytes[i], 2).PadLeft(8, '0'));
            }
            return sb.ToString();
        }

        private static byte[] BinaryToBytes(string binary)
        {
            string[] parts = binary.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            var byteList = new List<byte>();
            foreach (string part in parts)
            {
                if (part.Length <= 8)
                {
                    byteList.Add(Convert.ToByte(part, 2));
                }
                else
                {
                    // 8'li gruplara bol (soldan saga)
                    string padded = part;
                    int remainder = padded.Length % 8;
                    if (remainder != 0)
                        padded = padded.PadLeft(padded.Length + (8 - remainder), '0');
                    for (int j = 0; j < padded.Length; j += 8)
                        byteList.Add(Convert.ToByte(padded.Substring(j, 8), 2));
                }
            }
            return byteList.ToArray();
        }

        // ---- Decimal ----
        private static string BytesToDecimal(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 4);
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(bytes[i].ToString());
            }
            return sb.ToString();
        }

        private static byte[] DecimalToBytes(string dec)
        {
            string[] parts = dec.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            byte[] bytes = new byte[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                int val = int.Parse(parts[i]);
                if (val < 0 || val > 255)
                    throw new FormatException($"Decimal deger 0-255 araliginda olmali: {val}");
                bytes[i] = (byte)val;
            }
            return bytes;
        }

        // ---- Base64 ----
        private static byte[] Base64ToBytes(string b64)
        {
            // Bosluk temizle
            b64 = b64.Replace(" ", "").Replace("\t", "");
            // Eksik padding varsa otomatik ekle
            int mod = b64.Length % 4;
            if (mod != 0)
                b64 = b64.PadRight(b64.Length + (4 - mod), '=');
            return Convert.FromBase64String(b64);
        }
    }
}
