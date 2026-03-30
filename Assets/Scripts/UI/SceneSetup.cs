using UnityEngine;
using UnityEngine.UIElements;

namespace Kriptoloji.UI
{
    public class SceneSetup : MonoBehaviour
    {
        private void Awake()
        {
            CreateUI();
            Destroy(this);
        }

        private void CreateUI()
        {
            var visualTree = Resources.Load<VisualTreeAsset>("CryptoApp");
            if (visualTree == null)
            {
                Debug.LogError("CryptoApp.uxml Resources klasorunde bulunamadi! " +
                    "Assets/Resources/ altina kopyalayin veya UIDocument'e manuel atama yapin.");
                return;
            }

            GameObject uiGO = new GameObject("CryptoUI");
            var doc = uiGO.AddComponent<UIDocument>();

            // Editor scripti tarafindan olusturulan PanelSettings'i yukle
            var panelSettings = Resources.Load<PanelSettings>("CryptoPanelSettings");
            if (panelSettings != null)
                doc.panelSettings = panelSettings;

            doc.visualTreeAsset = visualTree;
            doc.sortingOrder = 0;

            uiGO.AddComponent<CryptoUIManager>();
        }
    }
}
