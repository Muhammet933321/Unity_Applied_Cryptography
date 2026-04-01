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
        private DropdownField otpFormat, otpKeyFormat, otpCipherFormat;
        private Label otpStatus;

        // DES
        private TextField desPlain, desKey, desCipher, desDecCipher, desDecKey, desDecOutput;
        private DropdownField desFormat, desKeyFormat, desCipherFormat;
        private Label desStatus;

        // AES
        private TextField aesPlain, aesKey, aesCipher, aesDecCipher, aesDecKey, aesDecOutput;
        private DropdownField aesKeySize, aesFormat, aesKeyFormat, aesCipherFormat;
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
            otpKeyFormat = root.Q<DropdownField>("otp-key-format");
            otpCipherFormat = root.Q<DropdownField>("otp-cipher-format");
            otpStatus = root.Q<Label>("otp-status");

            // DES fields
            desPlain = root.Q<TextField>("des-plain");
            desKey = root.Q<TextField>("des-key");
            desCipher = root.Q<TextField>("des-cipher");
            desDecCipher = root.Q<TextField>("des-dec-cipher");
            desDecKey = root.Q<TextField>("des-dec-key");
            desDecOutput = root.Q<TextField>("des-dec-output");
            desFormat = root.Q<DropdownField>("des-format");
            desKeyFormat = root.Q<DropdownField>("des-key-format");
            desCipherFormat = root.Q<DropdownField>("des-cipher-format");
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
            aesKeyFormat = root.Q<DropdownField>("aes-key-format");
            aesCipherFormat = root.Q<DropdownField>("aes-cipher-format");
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

            // Format degisim callback'leri -- veri formati
            RegisterFormatChangeCallback(otpFormat, otpStatus,
                new[] { otpPlain, otpDecOutput });
            RegisterFormatChangeCallback(desFormat, desStatus,
                new[] { desPlain, desDecOutput });
            RegisterFormatChangeCallback(aesFormat, aesStatus,
                new[] { aesPlain, aesDecOutput });

            // Format degisim callback'leri -- anahtar formati
            RegisterKeyFormatChangeCallback(otpKeyFormat, new[] { otpKey, otpDecKey });
            RegisterKeyFormatChangeCallback(desKeyFormat, new[] { desKey, desDecKey });
            RegisterKeyFormatChangeCallback(aesKeyFormat, new[] { aesKey, aesDecKey });

            // Format degisim callback'leri -- sifreli formati
            RegisterKeyFormatChangeCallback(otpCipherFormat, new[] { otpCipher, otpDecCipher });
            RegisterKeyFormatChangeCallback(desCipherFormat, new[] { desCipher, desDecCipher });
            RegisterKeyFormatChangeCallback(aesCipherFormat, new[] { aesCipher, aesDecCipher });

            // Girdi dogrulama callback'leri
            RegisterInputValidation(otpPlain, otpFormat);
            RegisterInputValidation(otpKey, otpKeyFormat);
            RegisterInputValidation(otpDecCipher, otpCipherFormat);
            RegisterInputValidation(otpDecKey, otpKeyFormat);

            RegisterInputValidation(desPlain, desFormat);
            RegisterInputValidation(desKey, desKeyFormat);
            RegisterInputValidation(desDecCipher, desCipherFormat);
            RegisterInputValidation(desDecKey, desKeyFormat);

            RegisterInputValidation(aesPlain, aesFormat);
            RegisterInputValidation(aesKey, aesKeyFormat);
            RegisterInputValidation(aesDecCipher, aesCipherFormat);
            RegisterInputValidation(aesDecKey, aesKeyFormat);

            ShowPanel("OTP");
        }

        // ==================== Girdi Dogrulama ====================
        private bool _isSanitizing;

        private void RegisterInputValidation(TextField field, DropdownField formatDropdown)
        {
            if (field == null || formatDropdown == null) return;
            field.RegisterValueChangedCallback(evt =>
            {
                if (_isSanitizing) return;
                OutputFormat fmt = GetSelectedFormat(formatDropdown);
                if (fmt == OutputFormat.Text || fmt == OutputFormat.ASCII) return;

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
            TextField[] textFields)
        {
            if (formatDropdown == null) return;
            formatDropdown.RegisterValueChangedCallback(evt =>
            {
                int oldIdx = System.Array.IndexOf(CryptoFormatter.FormatLabels, evt.previousValue);
                int newIdx = System.Array.IndexOf(CryptoFormatter.FormatLabels, evt.newValue);
                if (oldIdx < 0 || newIdx < 0 || oldIdx == newIdx) return;

                OutputFormat oldFmt = CryptoFormatter.FromIndex(oldIdx);
                OutputFormat newFmt = CryptoFormatter.FromIndex(newIdx);

                _isSanitizing = true;

                foreach (var field in textFields)
                    ConvertFieldValue(field, oldFmt, newFmt);

                _isSanitizing = false;
            });
        }

        private void RegisterKeyFormatChangeCallback(DropdownField keyFormatDropdown, TextField[] keyFields)
        {
            if (keyFormatDropdown == null) return;
            keyFormatDropdown.RegisterValueChangedCallback(evt =>
            {
                int oldIdx = System.Array.IndexOf(CryptoFormatter.FormatLabels, evt.previousValue);
                int newIdx = System.Array.IndexOf(CryptoFormatter.FormatLabels, evt.newValue);
                if (oldIdx < 0 || newIdx < 0 || oldIdx == newIdx) return;

                OutputFormat oldFmt = CryptoFormatter.FromIndex(oldIdx);
                OutputFormat newFmt = CryptoFormatter.FromIndex(newIdx);

                _isSanitizing = true;
                foreach (var field in keyFields)
                    ConvertFieldValue(field, oldFmt, newFmt);
                _isSanitizing = false;
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
                OutputFormat keyFmt = GetSelectedFormat(otpKeyFormat);
                OutputFormat cipherFmt = GetSelectedFormat(otpCipherFormat);

                int ptBits = CryptoFormatter.GetBitCount(plainInput, fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);

                if (fmt != OutputFormat.Text)
                    otpPlain.SetValueWithoutNotify(CryptoFormatter.BytesToFormat(ptBytes, fmt));

                string keyInput = otpKey.value;
                byte[] keyBytes;
                if (string.IsNullOrEmpty(keyInput))
                {
                    keyBytes = OTPGenerateKeyBytes(ptBytes.Length, keyFmt);
                    otpKey.value = CryptoFormatter.BytesToFormat(keyBytes, keyFmt);
                }
                else
                {
                    int keyBits = CryptoFormatter.GetBitCount(keyInput, keyFmt);
                    if (keyBits != ptBits)
                    {
                        SetStatus(otpStatus, $"OTP kurali: Anahtar ({keyBits} bit) ve metin ({ptBits} bit) bit uzunluklari esit olmali!", true);
                        return;
                    }
                    keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
                }

                byte[] cipherBytes = OTPCipher.Encrypt(ptBytes, keyBytes);
                otpCipher.value = CryptoFormatter.BytesToFormat(cipherBytes, cipherFmt);
                string msg = string.IsNullOrEmpty(keyInput)
                    ? "Sifreleme basarili! Anahtar otomatik uretildi."
                    : "Sifreleme basarili!";
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
                OutputFormat keyFmt = GetSelectedFormat(otpKeyFormat);
                OutputFormat cipherFmt = GetSelectedFormat(otpCipherFormat);

                int cipherBits = CryptoFormatter.GetBitCount(cipherInput, cipherFmt);
                int keyBits = CryptoFormatter.GetBitCount(keyInput, keyFmt);
                if (keyBits != cipherBits)
                {
                    SetStatus(otpStatus, $"OTP kurali: Anahtar ({keyBits} bit) ve sifreli metin ({cipherBits} bit) bit uzunluklari esit olmali!", true);
                    return;
                }

                byte[] cipherBytes = CryptoFormatter.FormatToBytes(cipherInput, cipherFmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
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
                OutputFormat keyFmt = GetSelectedFormat(otpKeyFormat);
                int ptBits = CryptoFormatter.GetBitCount(plainInput, fmt);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);

                if (fmt != OutputFormat.Text)
                    otpPlain.SetValueWithoutNotify(CryptoFormatter.BytesToFormat(ptBytes, fmt));

                byte[] keyBytes = OTPGenerateKeyBytes(ptBytes.Length, keyFmt);
                otpKey.value = CryptoFormatter.BytesToFormat(keyBytes, keyFmt);
                SetStatus(otpStatus, $"Anahtar uretildi ({ptBits} bit).", false);
            }
            catch (Exception ex)
            {
                SetStatus(otpStatus, "Hata: " + ex.Message, true);
            }
        }

        private byte[] OTPGenerateKeyBytes(int length, OutputFormat fmt)
        {
            if (fmt == OutputFormat.Text || fmt == OutputFormat.ASCII)
            {
                // Text/ASCII modda yazdiribilir ASCII uret (round-trip guvenli)
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
                OutputFormat keyFmt = GetSelectedFormat(desKeyFormat);
                OutputFormat cipherFmt = GetSelectedFormat(desCipherFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
                byte[] cipherBytes = DESCipher.Encrypt(ptBytes, keyBytes);
                desCipher.value = CryptoFormatter.BytesToFormat(cipherBytes, cipherFmt);
                SetStatus(desStatus, "DES sifreleme basarili!", false);
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
                OutputFormat keyFmt = GetSelectedFormat(desKeyFormat);
                OutputFormat cipherFmt = GetSelectedFormat(desCipherFormat);
                byte[] cipherBytes = CryptoFormatter.FormatToBytes(cipherInput, cipherFmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
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
            OutputFormat keyFmt = GetSelectedFormat(desKeyFormat);
            desKey.value = CryptoFormatter.BytesToFormat(key, keyFmt);
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
                OutputFormat keyFmt = GetSelectedFormat(aesKeyFormat);
                OutputFormat cipherFmt = GetSelectedFormat(aesCipherFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
                byte[] cipherBytes = AESCipher.Encrypt(ptBytes, keyBytes);
                aesCipher.value = CryptoFormatter.BytesToFormat(cipherBytes, cipherFmt);
                SetStatus(aesStatus, "AES sifreleme basarili!", false);
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
                OutputFormat keyFmt = GetSelectedFormat(aesKeyFormat);
                OutputFormat cipherFmt = GetSelectedFormat(aesCipherFormat);
                byte[] cipherBytes = CryptoFormatter.FormatToBytes(cipherInput, cipherFmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
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
            OutputFormat keyFmt = GetSelectedFormat(aesKeyFormat);
            aesKey.value = CryptoFormatter.BytesToFormat(key, keyFmt);
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
                OutputFormat keyFmt = GetSelectedFormat(otpKeyFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);

                string keyInput = otpKey.value;
                byte[] keyBytes = null;
                if (!string.IsNullOrEmpty(keyInput))
                {
                    keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);
                }

                var steps = CryptoVisualizer.VisualizeOTPEncrypt(ptBytes, keyBytes, fmt);
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
                OutputFormat keyFmt = GetSelectedFormat(desKeyFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);

                if (keyBytes.Length != 8)
                {
                    SetStatus(desStatus, "Anahtar 8 byte (64-bit) olmali!", true);
                    return;
                }

                var steps = CryptoVisualizer.VisualizeDESEncrypt(ptBytes, keyBytes, fmt);
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
                OutputFormat keyFmt = GetSelectedFormat(aesKeyFormat);
                byte[] ptBytes = CryptoFormatter.FormatToBytes(plainInput, fmt);
                byte[] keyBytes = CryptoFormatter.FormatToBytes(keyInput, keyFmt);

                var steps = CryptoVisualizer.VisualizeAESEncrypt(ptBytes, keyBytes, fmt);
                ShowVisualization(steps);
            }
            catch (Exception ex)
            {
                SetStatus(aesStatus, "Hata: " + ex.Message, true);
            }
        }
    }
}
