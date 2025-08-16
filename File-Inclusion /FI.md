# 📂 File Inclusion Rehberi (2025)
---
[1-Giriş ve Temel Kavramlar](/File-Inclusion/1-giris-ve-temel-kavramlar.md)
Açıklama: Local File Inclusion (LFI) ve Remote File Inclusion (RFI) kavramlarının tanıtımı, riskleri ve web uygulamalarındaki yaygın kullanım alanları.

---
[2-File Inclusion Açıklarının Temel Mantığı](/File-Inclusion/2-file-inclusion-aciklarinin-temel-mantigi.md)
Açıklama: Parametre bazlı dosya çağırma, input validation eksiklikleri, path traversal ve include/require fonksiyonlarının hatalı kullanımı.

---
[3-File Inclusion Türleri ve Riskleri](/File-Inclusion/3-file-inclusion-turleri-ve-riskleri.md)
Açıklama: LFI, RFI farkları, log poisoning, null byte injection, wrapper kullanımı gibi modern teknikler.

---
[4-Temel Saldırı Senaryoları](/File-Inclusion/4-temel-saldiri-senaryolari.md)
Açıklama: LFI/RFI üzerinden shell elde etme, konfigürasyon dosyalarını okuma, sensitive data sızdırma örnekleri.

---
[5-Payload ve Exploit Örnekleri](/File-Inclusion/5-payload-ve-exploit-ornekleri.md)
Açıklama: LFI / RFI için URL manipülasyonları, null byte, directory traversal, base64 veya wrapper bazlı payload örnekleri.

---
[6-Tespit ve Analiz Yöntemleri](/File-Inclusion/6-tespit-ve-analiz-yontemleri.md)
Açıklama: Manual test adımları, Burp Suite / OWASP ZAP kullanımı, otomatik tarayıcı ve scanner’lar, log analizi, monitoring.

---
[7-Olası Saldırılar ve Etkileri](/File-Inclusion/7-olasi-saldirilar-ve-etkileri.md)
Açıklama: RCE, sensitive data sızdırma, log file exploitation, server compromise senaryoları.

---
[8-WAF / Güvenlik Filtre Bypass Teknikleri](/File-Inclusion/8-waf-guvenlik-filtre-bypass-teknikleri.md)
Açıklama: URL encoding, double encoding, wrapper manipülasyonları, header / parameter tampering, bypass senaryoları.

---
[9-Önleme Yöntemleri ve Best Practices](/File-Inclusion/9-onleme-yontemleri-ve-best-practices.md)
Açıklama: Input validation, whitelist approach, safe include/require kullanımı, log ve monitoring, sandbox, WAF konfigürasyonu.

---
[10-Mülakat Soruları ve Çalışma Notları](/File-Inclusion/10-mulakat-sorulari-ve-calisma-notlari.md)
Açıklama: LFI/RFI farkları, exploit yöntemleri, savunma stratejileri ve scenario-based mülakat soruları.
