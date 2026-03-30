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
        private Label otpStatus;

        // DES
        private TextField desPlain, desKey, desCipher, desDecCipher, desDecKey, desDecOutput;
        private Label desStatus;

        // AES
        private TextField aesPlain, aesKey, aesCipher, aesDecCipher, aesDecKey, aesDecOutput;
        private DropdownField aesKeySize;
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
            otpStatus = root.Q<Label>("otp-status");

            // DES fields
            desPlain = root.Q<TextField>("des-plain");
            desKey = root.Q<TextField>("des-key");
            desCipher = root.Q<TextField>("des-cipher");
            desDecCipher = root.Q<TextField>("des-dec-cipher");
            desDecKey = root.Q<TextField>("des-dec-key");
            desDecOutput = root.Q<TextField>("des-dec-output");
            desStatus = root.Q<Label>("des-status");

            // AES fields
            aesPlain = root.Q<TextField>("aes-plain");
            aesKey = root.Q<TextField>("aes-key");
            aesCipher = root.Q<TextField>("aes-cipher");
            aesDecCipher = root.Q<TextField>("aes-dec-cipher");
            aesDecKey = root.Q<TextField>("aes-dec-key");
            aesDecOutput = root.Q<TextField>("aes-dec-output");
            aesKeySize = root.Q<DropdownField>("aes-keysize");
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

            ShowPanel("OTP");
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

        // ==================== OTP Islemleri ====================
        private void OTPEncrypt()
        {
            try
            {
                string plaintext = otpPlain.value;
                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(otpStatus, "Lutfen bir mesaj girin!", true);
                    return;
                }

                string textKey = otpKey.value;
                if (string.IsNullOrEmpty(textKey))
                {
                    var result = OTPCipher.EncryptString(plaintext);
                    otpKey.value = result.textKey;
                    otpCipher.value = result.ciphertextHex;
                    SetStatus(otpStatus, "Sifreleme basarili! Anahtar otomatik uretildi.", false);
                }
                else
                {
                    string cipherHex = OTPCipher.EncryptWithKey(plaintext, textKey);
                    otpCipher.value = cipherHex;
                    SetStatus(otpStatus, "Sifreleme basarili!", false);
                }
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
                string cipherHex = otpDecCipher.value.Trim();
                string textKey = otpDecKey.value;

                if (string.IsNullOrEmpty(cipherHex) || string.IsNullOrEmpty(textKey))
                {
                    SetStatus(otpStatus, "Sifreli metin ve anahtar gerekli!", true);
                    return;
                }

                string plaintext = OTPCipher.DecryptString(cipherHex, textKey);
                otpDecOutput.value = plaintext;
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
                string plaintext = otpPlain.value;
                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(otpStatus, "Once mesaj girin, anahtar mesaj uzunlugunda uretilir.", true);
                    return;
                }

                byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
                string textKey = OTPCipher.GenerateTextKey(plaintextBytes.Length);
                otpKey.value = textKey;
                SetStatus(otpStatus, $"Anahtar uretildi ({textKey.Length} karakter = {plaintextBytes.Length} byte).", false);
            }
            catch (Exception ex)
            {
                SetStatus(otpStatus, "Hata: " + ex.Message, true);
            }
        }

        // ==================== DES Islemleri ====================
        private void DESEncrypt()
        {
            try
            {
                string plaintext = desPlain.value;
                string keyHex = desKey.value.Trim();

                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(desStatus, "Lutfen bir mesaj girin!", true);
                    return;
                }

                if (string.IsNullOrEmpty(keyHex))
                {
                    SetStatus(desStatus, "Lutfen 8-byte (16 hex) anahtar girin veya uretin!", true);
                    return;
                }

                string cipherHex = DESCipher.EncryptString(plaintext, keyHex);
                desCipher.value = cipherHex;
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
                string cipherHex = desDecCipher.value.Trim();
                string keyHex = desDecKey.value.Trim();

                if (string.IsNullOrEmpty(cipherHex) || string.IsNullOrEmpty(keyHex))
                {
                    SetStatus(desStatus, "Sifreli metin ve anahtar gerekli!", true);
                    return;
                }

                string plaintext = DESCipher.DecryptString(cipherHex, keyHex);
                desDecOutput.value = plaintext;
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
            desKey.value = OTPCipher.BytesToHex(key);
            SetStatus(desStatus, "8-byte DES anahtari uretildi.", false);
        }

        // ==================== AES Islemleri ====================
        private void AESEncrypt()
        {
            try
            {
                string plaintext = aesPlain.value;
                string keyHex = aesKey.value.Trim();

                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(aesStatus, "Lutfen bir mesaj girin!", true);
                    return;
                }

                if (string.IsNullOrEmpty(keyHex))
                {
                    SetStatus(aesStatus, "Lutfen anahtar girin veya uretin!", true);
                    return;
                }

                string cipherHex = AESCipher.EncryptString(plaintext, keyHex);
                aesCipher.value = cipherHex;
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
                string cipherHex = aesDecCipher.value.Trim();
                string keyHex = aesDecKey.value.Trim();

                if (string.IsNullOrEmpty(cipherHex) || string.IsNullOrEmpty(keyHex))
                {
                    SetStatus(aesStatus, "Sifreli metin ve anahtar gerekli!", true);
                    return;
                }

                string plaintext = AESCipher.DecryptString(cipherHex, keyHex);
                aesDecOutput.value = plaintext;
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

            int keySizeBits = keySize * 8;
            string keyHex = AESCipher.GenerateKeyHex(keySizeBits);
            aesKey.value = keyHex;
            SetStatus(aesStatus, $"AES-{keySizeBits} anahtari uretildi ({keySize} byte).", false);
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
                string plaintext = otpPlain.value;
                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(otpStatus, "Gorsellestirme icin mesaj girin!", true);
                    return;
                }
                string textKey = otpKey.value;
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
                string plaintext = desPlain.value;
                string keyHex = desKey.value.Trim();
                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(desStatus, "Gorsellestirme icin mesaj girin!", true);
                    return;
                }
                if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 16)
                {
                    SetStatus(desStatus, "Gorsellestirme icin 16 hex karakter anahtar gerekli!", true);
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
                string plaintext = aesPlain.value;
                string keyHex = aesKey.value.Trim();
                if (string.IsNullOrEmpty(plaintext))
                {
                    SetStatus(aesStatus, "Gorsellestirme icin mesaj girin!", true);
                    return;
                }
                if (string.IsNullOrEmpty(keyHex))
                {
                    SetStatus(aesStatus, "Gorsellestirme icin anahtar gerekli!", true);
                    return;
                }
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
