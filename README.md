# AI-Based Network Intrusion Detection System (AI-IDS) 🛡️🤖

Bu proje, canlı ağ trafiğini soket seviyesinde dinleyerek (packet sniffing) siber saldırıları gerçek zamanlı olarak tespit eden **Yapay Zeka Tabanlı bir Ağ Saldırı Tespit Sistemi (IDS)** prototipidir. Proje, hem Kali Linux (Merkezi Sensör ve Dinleme Modülü) hem de Windows (Analiz ve Yönetim Paneli) ortamlarında çapraz platform uyumlu olarak çalışmaktadır.

## 🚀 Öne Çıkan Özellikler
* **Canlı Ağ Koklama (Sniffing):** `Scapy` altyapısı ile Layer 2 seviyesinde anlık ağ paket analizi.
* **Makine Öğrenmesi Gücü:** Trafik özniteliklerini sınıflandıran optimize edilmiş **Random Forest** modeli.
* **Gelişmiş Teşhis Modülleri:** Ağ körlüğünü engelleyen asenkron `run_linux_checks` ve `check_linux_packet_flow` mekanizmaları.
* **Kurumsal Grafik Arayüz:** `CustomTkinter` ile tasarlanmış modern, dinamik alarm paneli ve canlı istatistik grafikleri.

---

## 📊 Yazılım Kalitesi ve Mühendislik Metrikleri

### 1. Statik Kod Analizi (SonarQube)
Proje kaynak kodları SonarCloud platformu üzerinden denetlenmiş ve en yüksek temiz kod derecesi olan **Grade A** ile sertifikalandırılmıştır:
* **Security (Güvenlik):** %100 Temiz (0 Açık / 0 Risk)
* **Duplications (Kod Tekrarı):** %0.0 (Tamamen optimize ve modüler mimari)
* **Sürdürülebilirlik:** Teknik borç içermeyen clean-code yapısı.

### 2. Otomatik Teknik Dökümantasyon (Doxygen & Graphviz)
Projenin tüm sınıf ve metot mimarisi Doxygen ile taranmış, fonksiyonların birbirini tetikleme şemaları (Call/Caller Graphs) Graphviz motoru ile otomatik olarak çıkarılarak teknik kılavuz oluşturulmuştur.

### 3. FSM Yöntemi ile Emek Tahmini (Function Point & COCOMO)
Yazılım boyutlandırma süreçlerinde Function Point ve COCOMO modelleri entegre kullanılmıştır:
* **Yazılım Boyutu:** 34.1 FP (İşlev Puanı) ~ 1.807 Satır (KSLOC)
* **Toplam Mühendislik Emeği:** 814.72 Adam-Saat (5.36 Adam-Ay)

---

## 🛠️ Kurulum ve Çalıştırma

### Bağımlılıkların Yüklenmesi
Projeyi çalıştırmadan önce gerekli Python kütüphanelerini yükleyin:
```bash
pip install -r requirements.txt
