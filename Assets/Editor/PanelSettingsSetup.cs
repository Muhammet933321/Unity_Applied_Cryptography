using UnityEditor;
using UnityEngine;
using UnityEngine.UIElements;

namespace Kriptoloji.Editor
{
    [InitializeOnLoad]
    public static class PanelSettingsSetup
    {
        static PanelSettingsSetup()
        {
            // Mevcut asset varsa tema kontrolu yap
            var existing = Resources.Load<PanelSettings>("CryptoPanelSettings");
            if (existing != null && existing.themeStyleSheet != null)
                return;

            // Eski asset varsa sil (temasiz olusturulmustu)
            if (existing != null)
            {
                AssetDatabase.DeleteAsset("Assets/Resources/CryptoPanelSettings.asset");
                AssetDatabase.Refresh();
            }

            if (!AssetDatabase.IsValidFolder("Assets/Resources"))
                AssetDatabase.CreateFolder("Assets", "Resources");

            var ps = ScriptableObject.CreateInstance<PanelSettings>();
            ps.scaleMode = PanelScaleMode.ScaleWithScreenSize;
            ps.referenceResolution = new Vector2Int(1920, 1080);
            ps.screenMatchMode = PanelScreenMatchMode.MatchWidthOrHeight;
            ps.match = 0.5f;

            // Unity 6 varsayilan runtime temasini bul
            ThemeStyleSheet theme = FindRuntimeTheme();
            if (theme != null)
            {
                ps.themeStyleSheet = theme;
                Debug.Log($"Tema bulundu: {AssetDatabase.GetAssetPath(theme)}");
            }
            else
            {
                Debug.LogWarning("Varsayilan tema bulunamadi! " +
                    "Lutfen Create > UI Toolkit > Default Runtime Theme File ile olusturun " +
                    "ve CryptoPanelSettings'e atayiniz.");
            }

            AssetDatabase.CreateAsset(ps, "Assets/Resources/CryptoPanelSettings.asset");
            AssetDatabase.SaveAssets();
            AssetDatabase.Refresh();
            Debug.Log("CryptoPanelSettings.asset olusturuldu (Assets/Resources/)");
        }

        private static ThemeStyleSheet FindRuntimeTheme()
        {
            // Tum ThemeStyleSheet'leri ara
            string[] guids = AssetDatabase.FindAssets("t:ThemeStyleSheet");
            foreach (string guid in guids)
            {
                string path = AssetDatabase.GUIDToAssetPath(guid);
                // Runtime tema dosyalarini tercih et
                if (path.Contains("Runtime") || path.Contains("runtime") ||
                    path.Contains("UnityPanelSettings") || path.Contains("Default"))
                {
                    var t = AssetDatabase.LoadAssetAtPath<ThemeStyleSheet>(path);
                    if (t != null) return t;
                }
            }

            // Bulunamadiysa ilk mevcut temayikullan
            if (guids.Length > 0)
            {
                string path = AssetDatabase.GUIDToAssetPath(guids[0]);
                return AssetDatabase.LoadAssetAtPath<ThemeStyleSheet>(path);
            }

            return null;
        }
    }
}
