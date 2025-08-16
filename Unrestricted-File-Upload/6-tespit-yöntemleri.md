# 🔍 Tespit Yöntemleri (Detection Techniques)

Unrestricted File Upload açıklarının tespiti, hem saldırgan (Offensive Security) hem de savunmacı (Defensive Security) açısından kritik bir adımdır.  
Bu bölümde, bir web uygulamasında dosya yükleme zafiyetlerinin nasıl tespit edileceği, hangi araçların kullanılacağı, manuel test yöntemleri, PoC örnekleri, savunma yöntemleri ve mülakat soruları detaylı olarak ele alınacaktır.  

---

## 📌 1. Manuel Tespit Yöntemleri

Manuel analiz, pentester için en güvenilir yöntemlerden biridir çünkü otomasyon araçlarının gözden kaçırdığı durumları ortaya çıkarabilir.

- **Uzantı Manipülasyonu**  
  - `file.php` → `file.php.jpg`  
  - `shell.asp;.jpg`  
  - `evil.php%00.jpg` (Null byte injection)  

- **Content-Type Manipülasyonu**  
  HTTP isteğinde `Content-Type: image/jpeg` yazıp aslında PHP script göndermek.  

- **İsim Manipülasyonu**  
  Path traversal denemeleri:  
  `../../../../var/www/html/shell.php`  

- **Dosya İçeriği**  
  Zararsız görünümlü dosya içerisine **Polyglot payload** gömme:  
  Hem `JPEG` hem de `PHP` olarak parse edilebilen dosya.  

**Manuel Test Adımları:**  
1. Upload formunu bulun (profil resmi, belge yükleme, CV upload vb.).  
2. Normal bir dosya yükleyin → yanıtı analiz edin.  
3. Zararlı uzantılarla deneyin.  
4. Content-Type manipülasyonu yapın.  
5. Yüklenen dosyanın nereye kaydedildiğini tespit edin (response, predictable path, Burp Repeater).  

---

## ⚙️ 2. Otomasyon Araçları ile Tespit

Pentesterlar için zaman kazandırır. Ancak her zaman manuel testlerle desteklenmelidir.  

- **Burp Suite Intruder** → Uzantı brute force (php, asp, jsp vs.)  
- **OWASP ZAP** → File Upload fuzzing  
- **WFuzz / FFUF** → Dosya yolu brute force  
- **Nikto / Nuclei Templates** → Yaygın file upload misconfig tespiti  

**PoC Komutları:**  

- FFUF ile upload dizini brute force:  
  ffuf -u http://target.com/uploads/FUZZ -w wordlist.txt  

- Nuclei ile File Upload misconfig testi:  
  nuclei -t cves/ -tags upload  

---

## 📂 3. Log Analizi ile Tespit

Defensive yaklaşımda **Log Monitoring** kritik öneme sahiptir:  

- **Web Server Logs**  
  - `access.log` ve `error.log` içinde olağandışı dosya erişimleri  
  - `.php`, `.jsp`, `.asp` uzantılarıyla yüklenen dosyalar  
  - Dosya boyutunda anormallikler  

- **SIEM Kuralları**  
  - Örnek: “Web root altında `.php` yüklenmiş dosya” alarmı  
  - “/uploads/ dizininden çok sayıda request” → DoS denemesi  

---

## 💻 4. Örnek Tespit Senaryosu

**Senaryo:**  
Bir pentester, hedef uygulamanın profil resmi yükleme fonksiyonunu inceler.  

**Adımlar:**  
1. Normal bir `image.jpg` yüklenir → `/uploads/user123.jpg` yolunda bulunur.  
2. `shell.php` yüklenir → “Invalid file type” hatası.  
3. `shell.php.jpg` yüklenir → başarılı yüklenir.  
4. `/uploads/shell.php.jpg` ziyaret edilir → hata.  
5. `shell.php;.jpg` yüklenir → `/uploads/shell.php` olarak çalışır ve RCE sağlanır.  

**Çıkarım:** Sadece uzantı kontrolü yapılmış, MIME doğrulaması bypass edilebilmiş.  

---

## 🛡️ 5. Savunma Yöntemleri (Detection + Prevention)

- **Whitelisting** → Yalnızca belirli uzantılara izin ver (.jpg, .png, .pdf).  
- **MIME Type doğrulaması** → Hem istemci hem sunucu tarafında yapılmalı.  
- **File Signature (Magic Number) Kontrolü** → Gerçek dosya tipini içerikten doğrula.  
- **Upload Directory Isolation** → Web root dışında depola.  
- **WAF Kuralları** → File upload pattern tespiti.  
- **Monitoring** → SIEM entegrasyonu ile şüpheli yükleme aktiviteleri anlık olarak yakalanmalı.  
- **Antivirus / YARA Scanning** → Yüklenen dosya otomatik taranmalı.  

---

## ✅ Best Practices

1. Asla blacklist yaklaşımı kullanma → whitelist kullan.  
2. Tüm doğrulamaları **sunucu tarafında** yap.  
3. Kullanıcı tarafından gelen dosyaları **rename et** (UUID gibi).  
4. Upload edilen dosyaları **execute edilmeyecek** dizinlerde sakla.  
5. CDN veya ayrı domain üzerinden serve et → örn: `uploads.examplecdn.com`.  
6. Log’ları merkezi olarak topla ve alert mekanizması ekle.  

---

## 🎯 Mülakat Soruları

1. Unrestricted File Upload açığını manuel olarak nasıl tespit edersiniz?  
2. MIME Type ve Magic Number arasındaki fark nedir?  
3. Polyglot payload nedir, nasıl tespit edilebilir?  
4. Burp Suite kullanarak file upload bypass nasıl test edilir?  
5. Defensive açıdan log analizi ile bu açığı nasıl yakalarsınız?  
6. Upload edilen dosyanın direkt çalıştırılmasını engellemek için hangi yöntemleri önerirsiniz?  
7. “File upload zafiyetini exploit ettin. Hangi loglarda iz bırakmış olabilirsin?”  

---

## 📌 Sonuç

File Upload zafiyetlerinin **tespiti**, exploit edilmesinden çok daha önemlidir.  
Bir pentester için bypass tekniklerini bilmek, bir Blue Team için ise doğru logları analiz etmek kritik yetkinliktir.  
Günümüzde **CI/CD pipeline’larında, WAF’larda ve SIEM sistemlerinde** bu zafiyetlerin tespiti için proaktif kurallar oluşturmak, en iyi güvenlik pratiği olarak kabul edilmektedir.  
