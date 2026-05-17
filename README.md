# 🛡️ Zararlı URL Otomatik Sınıflandırma Sistemi

Bu proje, siber güvenlik tehdit istihbaratı kapsamında şüpheli URL'lerin analiz edilerek sınıflandırılmasını sağlayan otomatik bir veri boru hattı (pipeline) projesidir. Veritabanı Sistemleri dersi ödevi olarak hazırlanmıştır.

## 🚀 Proje Hakkında
Sisteme (Webhook aracılığıyla) gelen URL verileri yapay zeka/makine öğrenmesi konseptiyle (simüle edilerek) taranır, risk skorları belirlenir ve PostgreSQL veritabanına kaydedilir. İşlem sonucunda yetkililer için karanlık tema (dark mode) destekli, dinamik rozetlere sahip bir HTML güvenlik raporu üretilir.

## 🛠️ Kullanılan Teknolojiler
- **n8n (Nodmation):** İş akışı otomasyonu ve veri boru hattı (Data Pipeline) yönetimi.
- **PostgreSQL:** Yapılandırılmış verilerin (URL, kaynak, risk skoru, tarih) güvenli bir şekilde depolanması.
- **Docker:** Veritabanı ve n8n ortamının bağımsız konteynerler (container) halinde izole çalıştırılması.
- **HTML & JavaScript:** Son kullanıcı/analist için üretilen görsel tehdit istihbarat raporunun tasarlanması.

## ⚙️ Kurulum ve Çalıştırma (Docker)
Proje tamamen Docker üzerinde çalışacak şekilde tasarlanmıştır.

1. **Veritabanını Başlatın:**
   ```bash
   docker run -d --name selin_postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=selin123 -e POSTGRES_DB=url_veritabani -p 5433:5432 postgres
   ```
2. **Tabloyu Oluşturun:**
   ```bash
   docker exec selin_postgres psql -U postgres -d url_veritabani -c "CREATE TABLE url_analiz (id INT, url VARCHAR(255), kaynak VARCHAR(100), risk_skoru INT, siniflandirma VARCHAR(50), tarih VARCHAR(50));"
   ```
3. **n8n Akışını İçe Aktarın:**
   Projeye ait `Zararli_URL_Siniflandirma.json` dosyasını n8n arayüzünden "Import from File" seçeneği ile içe aktarın ve çalıştırın.

## 📊 Rapor Ekranı Özellikleri
Sistem çalıştığında Webhook üzerinden anında üretilen HTML raporu, aşağıdaki tehdit kategorilerini renkli rozetlerle sunmaktadır:
- 🟢 **Güvenli** (Risk Skoru: 0-10)
- 🟡 **Şüpheli** (Risk Skoru: 11-75)
- 🔴 **Phishing / Oltalama** (Risk Skoru: 76-100)
- 🔴 **Malware / Zararlı Yazılım** (Risk Skoru: 76-100)
