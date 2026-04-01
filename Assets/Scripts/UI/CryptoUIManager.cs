using UnityEngine;
using UnityEngine.UIElements;
using System;
using System.Collections.Generic;
using Kriptoloji.Crypto;

namespace Kriptoloji.UI
{
    [RequireComponent(typeof(UIDocument))]
    public class CryptoUIManager : MonoBehaviour
    {
        // OTP
        private TextField otpPlain, otpKey, otpCipher, otpDecCipher, otpDecKey, otpDecOutput;
        private DropdownField otpFormat;
        private Label otpStatus;

        // DES
        private TextField desPlain, desKey, desCipher, desDecCipher, desDecKey, desDecOutput;
        private DropdownField desFormat;
        private Label desStatus;

        // AES
        private TextField aesPlain, aesKey, aesCipher, aesDecCipher, aesDecKey, aesDecOutput;
        private DropdownField aesKeySize, aesFormat;
        private Label aesStatus;

        // Panels & Tabs
        private VisualElement otpPanel, desPanel, aesPanel;
        private Button tabOtp, tabDes, tabAes;

        // Visualization
        private VisualElement visualOverlay;
        private Label visualText;

        private void OnEnable()
        {
            var root = GetComponent<UIDocument>().rootVisualElement;

            // Tabs
            tabOtp = root.Q<Button>("tab-otp");
            tabDes = root.Q<Button>("tab-des");
            tabAes = root.Q<Button>("tab-aes");

            // Panels
            otpPanel = root.Q<VisualElement>("panel-otp");
            desPanel = root.Q<VisualElement>("panel-des");
            aesPanel = root.Q<VisualElement>("panel-aes");

            // OTP fields
            otpPlain = root.Q<TextField>("otp-plain");
            otpKey = root.Q<TextField>("otp-key");
            otpCipher = root.Q<TextField>("otp-cipher");
            otpDecCipher = root.Q<TextField>("otp-dec-cipher");
            otpDecKey = root.Q<TextField>("otp-dec-key");
            otpDecOutput = root.Q<TextField>("otp-dec-output");
            otpFormat = root.Q<DropdownField>("otp-format");
            otpStatus = root.Q<Label>("otp-status");

            // DES fields
            desPlain = root.Q<TextField>("des-plain");
            desKey = root.Q<TextField>("des-key");
            desCipher = root.Q<TextField>("des-cipher");
            desDecCipher = root.Q<TextField>("des-dec-cipher");
            desDecKey = root.Q<TextField>("des-dec-key");
            desDecOutput = root.Q<TextField>("des-dec-output");
            desFormat = root.Q<DropdownField>("des-format");
            desStatus = root.Q<Label>("des-status");

            // AES fields
            aesPlain = root.Q<TextField>("aes-plain");
            aesKey = root.Q<TextField>("aes-key");
            aesCipher = root.Q<TextField>("aes-cipher");
            aesDecCipher = root.Q<TextField>("aes-dec-cipher");
            aesDecKey = root.Q<TextField>("aes-dec-key");
            aesDecOutput = root.Q<TextField>("aes-dec-output");
            aesKeySize = root.Q<DropdownField>("aes-keysize");
            aesFormat = root.Q<DropdownField>("aes-format");
            aesStatus = root.Q<Label>("aes-status");

            // Visualization
            visualOverlay = root.Q<VisualElement>("visual-overlay");
            visualText = root.Q<Label>("visual-text");

            // Tab clicks
            tabOtp.clicked += () => ShowPanel("OTP");
            tabDes.clicked += () => ShowPanel("DES");
            tabAes.clicked += () => ShowPanel("AES");

            // OTP buttons
            root.Q<Button>("otp-genkey").clicked += OTPGenerateKey;
            root.Q<Button>("otp-encrypt").clicked += OTPEncrypt;
            root.Q<Button>("otp-visualize").clicked += OTPVisualize;
            root.Q<Button>("otp-decrypt").clicked += OTPDecrypt;

            // DES buttons
            root.Q<Button>("des-genkey").clicked += DESGenerateKey;
            root.Q<Button>("des-encrypt").clicked += DESEncrypt;
            root.Q<Button>("des-visualize").clicked += DESVisualize;
            root.Q<Button>("des-decrypt").clicked += DESDecrypt;

            // AES buttons
            root.Q<Button>("aes-genkey").clicked += AESGenerateKey;
            root.Q<Button>("aes-encrypt").clicked += AESEncrypt;
            root.Q<Button>("aes-visualize").clicked += AESVisualize;
            root.Q<Button>("aes-decrypt").clicked += AESDecrypt;

            // Visual close
            root.Q<Button>("visual-close").clicked += () =>
                visualOverlay.RemoveFromClassList("overlay-active");

            // Format degisim callback'leri (format switch = alan donusumu)
            RegisterFormatChangeCallback(otpFormat, otpStatus,
                new[] { otpPlain, otpKey, otpDecKey },
                new[] { otpCipher, otpDecCipher, otpDecOutput },
                true);
            RegisterFormatChangeCallback(desFormat, desStatus,
                new[] { desPlain },
                new[] { desKey, desCipher, desDecCipher, desDecKey, desDecOutput },
                false);
            RegisterFormatChangeCallback(aesFormat, aesStatus,
                new[] { aesPlain },
                new[] { aesKey, aesCipher, aesDecCipher, aesDecKey, aesDecOutput },
                false);

            // Girdi dogrulama callback'leri
            RegisterInputValidation(otpPlain, otpFormat, false);
            RegisterInputValidation(otpKey, otpFormat, false);
            RegisterInputValidation(otpDecCipher, otpFormat, true);
            RegisterInputValidation(otpDecKey, otpFormat, false);

            RegisterInputValidation(desPlain, desFormat, false);
            RegisterInputValidation(desKey, desFormat, true);
            RegisterInputValidation(desDecCipher, desFormat, true);
            RegisterInputValidation(desDecKey, desFormat, true);

            RegisterInputValidation(aesPlain, aesFormat, false);
            RegisterInputValidation(aesKey, aesFormat, true);
            RegisterInputValidation(aesDecCipher, aesFormat, true);
            RegisterInputValidation(aesDecKey, aesFormat, true);

            ShowPanel("OTP");
        }

        // ==================== Girdi Dogrulama ====================
        private bool _isSanitizing;

        private void RegisterInputValidation(TextField field, DropdownField formatDropdown, bool isCipherField)
        {
            if (field == null || formatDropdown == null) return;
            field.RegisterValueChangedCallback(evt =>
            {
                if (_isSanitizing) return;
                OutputFormat fmt = GetSelectedFormat(formatDropdown);
                if (isCipherField)
                    fmt = CryptoFormatter.GetCipherFormat(fmt);
                if (fmt == OutputFormat.Text) return;

                string sanitized = CryptoFormatter.SanitizeInput(evt.newValue, fmt);
                if (sanitized != evt.newValue)
                {
                    _isSanitizing = true;
                    field.value = sanitized;
                    _isSanitizing = false;
                    field.AddToClassList("input-error");
                }
                else
                {
                    field.RemoveFromClassList("input-error");
                }
            });
        }

        // ==================== Format Degisim Donusumu ====================
        private void RegisterFormatChangeCallback(
            DropdownField formatDropdown,
            Label statusLabel,
            TextField[] textFields,
            TextField[] cipherFields,
            bool isOtp)
        {
            if (formatDropdown == null) return;
            formatDropdown.RegisterValueChangedCallback(evt =>
            {
                int oldIdx = System.Array.IndexOf(CryptoFormatter.FormatLabels, evt.previousValue);
                int newIdx = System.Array.IndexOf(CryptoFormatter.FormatLabels, evt.newValue);
                if (oldIdx < 0 || newIdx < 0 || oldIdx == newIdx) return;

                OutputFormat oldFmt = CryptoFormatter.FromIndex(oldIdx);
                OutputFormat newFmt = CryptoFormatter.FromIndex(newIdx);
                OutputFormat oldCipherFmt = CryptoFormatter.GetCipherFormat(oldFmt);
                OutputFormat newCipherFmt = CryptoFormatter.GetCipherFormat(newFmt);

                _isSanitizing = true;

                // Duz metin alanlari (Text formatiyla calisan)
                foreach (var field in textFields)
                    ConvertFieldValue(field, oldFmt, newFmt);

                // Sifreli/anahtar alanlari (cipher formatiyla calisan)
                foreach (var field in cipherFields)
                    ConvertFieldValue(field, oldCipherFmt, newCipherFmt);

                _isSanitizing = false;

                if (newFmt == OutputFormat.Text && !isOtp)
                    SetStatus(statusLabel, "Text modda anahtar ve sifreli metin Hex olarak gosterilir.", false);
            });
        }

        private void ConvertFieldValue(TextField field, OutputFormat oldFmt, OutputFormat newFmt)
        {
            if (field == null || string.IsNullOrEmpty(field.value)) return;
            try
            {
                byte[] bytes = CryptoFormatter.FormatToBytes(field.value, oldFmt);
                field.value = CryptoFormatter.BytesToFormat(bytes, newFmt);
                field.RemoveFromClassList("input-error");
            }
            catch
            {
                field.value = "";
            }
        }

        // ==================== Panel Yonetimi ====================
        private void ShowPanel(string panelName)
        {
            SetPanelActive(otpPanel, panelName == "OTP");
            SetPanelActive(desPanel, panelName == "DES");
            SetPanelActive(aesPanel, panelName == "AES");

            SetTabActive(tabOtp, panelName == "OTP");
            SetTabActive(tabDes, panelName == "DES");
            SetTabActive(tabAes, panelName == "AES");
        }

        private void SetPanelActive(VisualElement panel, bool active)
        {
            if (active)
                panel.AddToClassList("panel-active");
            else
                panel.RemoveFromClassList("panel-active");
        }

        private void SetTabActive(Button tab, bool active)
        {
            if (active)
                tab.AddToClassList("tab-active");
            else
                tab.RemoveFromClassList("tab-active");
        }

        private OutputFormat GetSelectedFormat(DropdownField dropdown)
        {
            if (dropdown == null) return OutputFormat.Hex;
            return CryptoFormatter.FromIndex(dropdown.index);
        }

        // ==================== OTP Islemleri ====================
        private void OTPEncrypt()
        {
            try
            {
                string plainInput = otpPlain.value;
                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(otpStatus, "Lutfen bir mesaj girin!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(otpFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);

                // Girdiyi normalize et (orn. binary "1001" -> "00001001")
                if (fmt != OutputFormat.Text)
                    otpPlain.SetValueWithoutNotify(CryptoFormatter.BytesToFormat(ptBytes, fmt));

                string keyInput = otpKey.value;
                byte[] keyBytes;
                if (string.IsNullOrEmpty(keyInput))
                {
                    keyBytes = OTPGenerateKeyBytes(ptBytes.Length, fmt);
                    otpKey.value = CryptoFormatter.BytesToFormat(keyBytes, fmt);
                }
                else
                {
                    keyBytes = CryptoFormatter.FormatToBytes(keyInput, fmt);
                    if (keyBytes.Length != ptBytes.Length)
                    {
                        SetStatus(otpStatus, $"OTP kurali: Anahtar ({keyBytes.Length} byte) ve metin ({ptBytes.Length} byte) ayni uzunlukta olmali!", true);
                        return;
                    }
                }

                byte[] cipherBytes = OTPCipher.Encrypt(ptBytes, keyBytes);
                otpCipher.value = CryptoFormatter.BytesToFormat(cipherBytes, cipherFmt);
                string msg = string.IsNullOrEmpty(keyInput)
                    ? "Sifreleme basarili! Anahtar otomatik uretildi."
                    : "Sifreleme basarili!";
                if (fmt == OutputFormat.Text)
                    msg += " (Sifreli metin Hex olarak gosteriliyor)";
                SetStatus(otpStatus, msg, false);
            }
            catch (Exception ex)
            {
                SetStatus(otpStatus, "Hata: " + ex.Message, true);
            }
        }

        private void OTPDecrypt()
        {
            try
            {
                string cipherInput = otpDecCipher.value.Trim();
                string keyInput = otpDecKey.value;

                if (string.IsNullOrEmpty(cipherInput) || string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(otpStatus, "Sifreli metin ve anahtar gerekli!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(otpFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] cipherBytes = CryptoFormatter.FormatToBytes(cipherInput, cipherFmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, fmt);
                if (keyBytes.Length != cipherBytes.Length)
                {
                    SetStatus(otpStatus, $"OTP kurali: Anahtar ({keyBytes.Length} byte) ve sifreli metin ({cipherBytes.Length} byte) ayni uzunlukta olmali!", true);
                    return;
                }
                byte[] plainBytes = OTPCipher.Decrypt(cipherBytes, keyBytes);
                otpDecOutput.value = CryptoFormatter.BytesToFormat(plainBytes, fmt);
                SetStatus(otpStatus, "Cozme basarili!", false);
            }
            catch (Exception ex)
            {
                SetStatus(otpStatus, "Hata: " + ex.Message, true);
            }
        }

        private void OTPGenerateKey()
        {
            try
            {
                string plainInput = otpPlain.value;
                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(otpStatus, "Once mesaj girin, anahtar mesaj uzunlugunda uretilir.", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(otpFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);

                // Girdiyi normalize et
                if (fmt != OutputFormat.Text)
                    otpPlain.SetValueWithoutNotify(CryptoFormatter.BytesToFormat(ptBytes, fmt));

                byte[] keyBytes = OTPGenerateKeyBytes(ptBytes.Length, fmt);
                otpKey.value = CryptoFormatter.BytesToFormat(keyBytes, fmt);
                SetStatus(otpStatus, $"Anahtar uretildi ({ptBytes.Length} byte).", false);
            }
            catch (Exception ex)
            {
                SetStatus(otpStatus, "Hata: " + ex.Message, true);
            }
        }

        private byte[] OTPGenerateKeyBytes(int length, OutputFormat fmt)
        {
            if (fmt == OutputFormat.Text)
            {
                // Text modda yazdirabilir ASCII uret (UTF-8 round-trip guvenli)
                string textKey = OTPCipher.GenerateTextKey(length);
                return System.Text.Encoding.UTF8.GetBytes(textKey);
            }
            return OTPCipher.GenerateKey(length);
        }

        // ==================== DES Islemleri ====================
        private void DESEncrypt()
        {
            try
            {
                string plainInput = desPlain.value;
                string keyInput = desKey.value.Trim();

                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(desStatus, "Lutfen bir mesaj girin!", true);
                    return;
                }

                if (string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(desStatus, "Lutfen 8-byte anahtar girin veya uretin!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(desFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, cipherFmt);
                byte[] cipherBytes = DESCipher.Encrypt(ptBytes, keyBytes);
                desCipher.value = CryptoFormatter.BytesToFormat(cipherBytes, cipherFmt);
                string msg = "DES sifreleme basarili!";
                if (fmt == OutputFormat.Text)
                    msg += " (Anahtar ve sifreli metin Hex olarak gosteriliyor)";
                SetStatus(desStatus, msg, false);
            }
            catch (Exception ex)
            {
                SetStatus(desStatus, "Hata: " + ex.Message, true);
            }
        }

        private void DESDecrypt()
        {
            try
            {
                string cipherInput = desDecCipher.value.Trim();
                string keyInput = desDecKey.value.Trim();

                if (string.IsNullOrEmpty(cipherInput) || string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(desStatus, "Sifreli metin ve anahtar gerekli!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(desFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] cipherBytes = CryptoFormatter.FormatToBytes(cipherInput, cipherFmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, cipherFmt);
                byte[] plainBytes = DESCipher.Decrypt(cipherBytes, keyBytes);
                desDecOutput.value = CryptoFormatter.BytesToFormat(plainBytes, fmt);
                SetStatus(desStatus, "DES cozme basarili!", false);
            }
            catch (Exception ex)
            {
                SetStatus(desStatus, "Hata: " + ex.Message, true);
            }
        }

        private void DESGenerateKey()
        {
            byte[] key = new byte[8];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            OutputFormat fmt = GetSelectedFormat(desFormat);
            OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
            desKey.value = CryptoFormatter.BytesToFormat(key, cipherFmt);
            SetStatus(desStatus, "8-byte DES anahtari uretildi.", false);
        }

        // ==================== AES Islemleri ====================
        private void AESEncrypt()
        {
            try
            {
                string plainInput = aesPlain.value;
                string keyInput = aesKey.value.Trim();

                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(aesStatus, "Lutfen bir mesaj girin!", true);
                    return;
                }

                if (string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(aesStatus, "Lutfen anahtar girin veya uretin!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(aesFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, cipherFmt);
                byte[] cipherBytes = AESCipher.Encrypt(ptBytes, keyBytes);
                aesCipher.value = CryptoFormatter.BytesToFormat(cipherBytes, cipherFmt);
                string msg = "AES sifreleme basarili!";
                if (fmt == OutputFormat.Text)
                    msg += " (Anahtar ve sifreli metin Hex olarak gosteriliyor)";
                SetStatus(aesStatus, msg, false);
            }
            catch (Exception ex)
            {
                SetStatus(aesStatus, "Hata: " + ex.Message, true);
            }
        }

        private void AESDecrypt()
        {
            try
            {
                string cipherInput = aesDecCipher.value.Trim();
                string keyInput = aesDecKey.value.Trim();

                if (string.IsNullOrEmpty(cipherInput) || string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(aesStatus, "Sifreli metin ve anahtar gerekli!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(aesFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] cipherBytes = CryptoFormatter.FormatToBytes(cipherInput, cipherFmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, cipherFmt);
                byte[] plainBytes = AESCipher.Decrypt(cipherBytes, keyBytes);
                aesDecOutput.value = CryptoFormatter.BytesToFormat(plainBytes, fmt);
                SetStatus(aesStatus, "AES cozme basarili!", false);
            }
            catch (Exception ex)
            {
                SetStatus(aesStatus, "Hata: " + ex.Message, true);
            }
        }

        private void AESGenerateKey()
        {
            int keySize = 16;
            if (aesKeySize != null)
            {
                switch (aesKeySize.index)
                {
                    case 0: keySize = 16; break;
                    case 1: keySize = 24; break;
                    case 2: keySize = 32; break;
                }
            }

            byte[] key = new byte[keySize];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            OutputFormat fmt = GetSelectedFormat(aesFormat);
            OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
            aesKey.value = CryptoFormatter.BytesToFormat(key, cipherFmt);
            SetStatus(aesStatus, $"AES-{keySize * 8} anahtari uretildi ({keySize} byte).", false);
        }

        // ==================== Yardimci ====================
        private void SetStatus(Label statusLabel, string message, bool isError)
        {
            if (statusLabel == null) return;
            statusLabel.text = message;
            if (isError)
                statusLabel.AddToClassList("status-error");
            else
                statusLabel.RemoveFromClassList("status-error");
        }

        // ==================== Gorsellestirme ====================
        private void ShowVisualization(List<string> steps)
        {
            if (visualOverlay == null || visualText == null) return;
            visualText.text = string.Join("\n", steps);
            visualOverlay.AddToClassList("overlay-active");
        }

        private void OTPVisualize()
        {
            try
            {
                string plainInput = otpPlain.value;
                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(otpStatus, "Gorsellestirme icin mesaj girin!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(otpFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                string plaintext = System.Text.Encoding.UTF8.GetString(ptBytes);

                string keyInput = otpKey.value;
                string textKey = null;
                if (!string.IsNullOrEmpty(keyInput))
                {
                    byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, fmt);
                    textKey = System.Text.Encoding.UTF8.GetString(keyBytes);
                }

                var steps = CryptoVisualizer.VisualizeOTPEncrypt(plaintext, textKey);
                ShowVisualization(steps);
            }
            catch (Exception ex)
            {
                SetStatus(otpStatus, "Hata: " + ex.Message, true);
            }
        }

        private void DESVisualize()
        {
            try
            {
                string plainInput = desPlain.value;
                string keyInput = desKey.value.Trim();
                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(desStatus, "Gorsellestirme icin mesaj girin!", true);
                    return;
                }
                if (string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(desStatus, "Gorsellestirme icin anahtar gerekli!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(desFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                string plaintext = System.Text.Encoding.UTF8.GetString(ptBytes);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, cipherFmt);
                string keyHex = OTPCipher.BytesToHex(keyBytes);

                if (keyHex.Length != 16)
                {
                    SetStatus(desStatus, "Anahtar 8 byte (64-bit) olmali!", true);
                    return;
                }

                var steps = CryptoVisualizer.VisualizeDESEncrypt(plaintext, keyHex);
                ShowVisualization(steps);
            }
            catch (Exception ex)
            {
                SetStatus(desStatus, "Hata: " + ex.Message, true);
            }
        }

        private void AESVisualize()
        {
            try
            {
                string plainInput = aesPlain.value;
                string keyInput = aesKey.value.Trim();
                if (string.IsNullOrEmpty(plainInput))
                {
                    SetStatus(aesStatus, "Gorsellestirme icin mesaj girin!", true);
                    return;
                }
                if (string.IsNullOrEmpty(keyInput))
                {
                    SetStatus(aesStatus, "Gorsellestirme icin anahtar gerekli!", true);
                    return;
                }

                OutputFormat fmt = GetSelectedFormat(aesFormat);
                OutputFormat cipherFmt = CryptoFormatter.GetCipherFormat(fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                string plaintext = System.Text.Encoding.UTF8.GetString(ptBytes);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, cipherFmt);
                string keyHex = OTPCipher.BytesToHex(keyBytes);

                var steps = CryptoVisualizer.VisualizeAESEncrypt(plaintext, keyHex);
                ShowVisualization(steps);
            }
            catch (Exception ex)
            {
                SetStatus(aesStatus, "Hata: " + ex.Message, true);
            }
        }
    }
}
