# 🛡️ Önleme Yöntemleri (Prevention Techniques) – Unrestricted File Upload

Unrestricted File Upload açıkları, saldırganların zararlı dosya yükleyerek sistem üzerinde kontrol sağlamasına imkân verir. Bu bölüm, web uygulamalarında **güncel ve etkili önleme yöntemlerini**, PoC örnekleri ve best practice’leri içermektedir. Ayrıca mülakatlarda sorulabilecek sorulara hazırlık sağlar.

---

## 📌 1. Dosya Uzantısı ve MIME Tipi Kontrolü

**Açıklama:**  
Sadece güvenli dosya türlerinin yüklenmesine izin verilmelidir. Dosya uzantısı tek başına güvenli değildir; MIME tipi de doğrulanmalıdır.

**PoC Örneği:**  
- Yalnızca `.jpg`, `.png`, `.pdf` izinli.  
- MIME doğrulama örneği: `image/jpeg`, `application/pdf`.

**Kullanım:**  
- Sunucu tarafında aşağıdaki doğrulamayı yap:
  - Uzantı kontrolü → whitelist  
  - MIME kontrolü → Magic Byte veya Content-Type doğrulama

**Sonuç:**  
- Script dosyalarının yüklenmesi engellenir.  
- Polyglot ve disguised payload’lar minimize edilir.

---

## 📌 2. Dosya İsmi Sanitizasyonu ve Randomize Etme

**Açıklama:**  
Kullanıcı tarafından yüklenen dosya isimleri, sistem üzerinde path traversal veya overwrite saldırılarına sebep olabilir.

**PoC Örneği:**  
- Kullanıcı yükledi: `../../shell.php`  
- Sistem randomize isimle kaydetti: `f1a3b7c9.jpg`

**Kullanım:**  
- Dosya isimlerini sanitize et: özel karakterleri kaldır.  
- Random veya UUID ile yeniden adlandır.  
- Upload dizininde nested path kullanımını engelle.

**Sonuç:**  
- Path traversal saldırıları önlenir.  
- Overwrite riski minimize edilir.

---

## 📌 3. Upload Dizini İzolasyonu

**Açıklama:**  
Dosyaların web root dışında veya execute edilmeyen dizinlerde depolanması.

**PoC Örneği:**  
- `/var/www/uploads` → sadece veri depolama  
- Web server execute izni yok

**Kullanım:**  
- Upload dizini: `/uploads`  
- `.htaccess` veya server config ile script çalıştırmayı engelle

**Sonuç:**  
- Dosya yüklenmiş olsa bile RCE ihtimali ortadan kalkar.  

---

## 📌 4. İçerik Tarama ve Antivirüs

**Açıklama:**  
Yüklenen dosyalar sunucu tarafında otomatik olarak taranmalı. Malware, trojan veya zararlı script tespiti yapılmalıdır.

**PoC Örneği:**  
- ClamAV taraması: `clamscan /uploads/*`  
- Sandbox testleri → Macro veya exe dosyalarını analiz et

**Kullanım:**  
- Dosya yükleme sonrası tarama adımı ekle  
- Şüpheli dosyalar reddedilir veya karantinaya alınır

**Sonuç:**  
- Malware ve trojan bulaşmaları önlenir  
- Kullanıcılar güvenli dosya kullanır

---

## 📌 5. Dosya Boyutu ve Rate Limiting

**Açıklama:**  
Büyük dosyalar DoS riskini artırır. Ayrıca, ardışık yüklemeler brute force veya resource exhaustion saldırılarına neden olabilir.

**PoC Örneği:**  
- Max upload size: 2 MB  
- Max 10 upload / dakika per IP

**Kullanım:**  
- Sunucu ve uygulama tarafında dosya boyutu limiti uygula  
- Rate limit ile upload sıklığını sınırla

**Sonuç:**  
- Disk dolumu veya sistem performans sorunları engellenir  
- Brute force ve DoS atakları minimize edilir

---

## 📌 6. WAF / Güvenlik Katmanı

**Açıklama:**  
WAF, dosya yükleme formlarını ve payload’ları izler, şüpheli aktiviteleri filtreler.

**PoC Örneği:**  
- OWASP CRS kuralları  
- Payload filtreleme → `<script>` veya `<?php` tespiti

**Kullanım:**  
- File upload endpoint’lerini özel WAF kuralları ile koru  
- Anomaly detection ve logging aktif

**Sonuç:**  
- Saldırganın bilinen payload’ları yüklemesi zorlaşır  
- Loglar üzerinden analiz yapılabilir

---

## 📌 7. Logging ve Monitoring

**Açıklama:**  
Dosya yüklemeleri merkezi loglara kaydedilmeli, şüpheli aktiviteler tespit edilmelidir.

**PoC Örneği:**  
- `access.log` → olağan dışı dosya uzantıları  
- SIEM entegrasyonu → anormal upload davranışları

**Kullanım:**  
- Upload aktivitelerini logla  
- Anomaly veya alert mekanizmaları ekle

**Sonuç:**  
- Potansiyel saldırılar erken tespit edilir  
- Forensic ve audit için veri sağlanır

---

## 💡 Mülakat Soruları

1. File upload güvenliği için en kritik önlemler nelerdir?  
2. Neden sadece dosya uzantısına güvenmek yeterli değildir?  
3. Dosya isimlerini sanitize etmezsek hangi saldırılar gerçekleşebilir?  
4. Upload dizini izolasyonu nasıl uygulanır ve neden önemlidir?  
5. Antivirüs ve sandbox taraması file upload güvenliğinde nasıl rol oynar?  
6. Rate limit ve dosya boyutu kontrolü hangi saldırıları önler?  
7. WAF, logging ve monitoring file upload güvenliğinde nasıl entegre edilir?

---

## ✅ Sonuç

File upload önleme yöntemleri, **çok katmanlı ve birbirini destekleyen güvenlik önlemleri** ile sağlanmalıdır.  
- Uzantı ve MIME doğrulama  
- Dosya adı sanitizasyonu ve randomize etme  
- İzole dizin ve execute engeli  
- Antivirüs / sandbox tarama  
- Boyut limiti ve rate limiting  
- WAF ve logging / monitoring  

Bu önlemler eksiksiz uygulandığında, Unrestricted File Upload kaynaklı riskler büyük ölçüde minimize edilir.  
