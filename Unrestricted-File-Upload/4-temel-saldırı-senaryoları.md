## 🎯 Temel Saldırı Senaryoları

Bu bölümde dosya yükleme açıklarının **güncel saldırı senaryoları** ele alınacaktır. Amaç, bir pentester veya güvenlik uzmanının hem **istismar tekniklerini** hem de **savunma yöntemlerini** anlamasını sağlamaktır. Ayrıca, mülakatlarda sıkça sorulan pratik sorular da eklenmiştir.

---

### 1) Web Shell Yükleme (Remote Code Execution - RCE)

**Senaryo**:  
- Uygulama sadece dosya uzantısını kontrol ediyor.  
- Saldırgan, `.php` dosyası yerine `.php.jpg` uzantılı zararlı dosya yükler.  
- Sunucu uzantıya güvenerek dosyayı kabul eder, dosya web root altında kaydedilir.  
- Saldırgan dosyayı çağırarak komut çalıştırır.

**PoC (Proof of Concept)**:  
Dosya adı: `shell.php.jpg`  
Dosya içeriği:
<?php system($_GET['cmd']); ?>

**Saldırı Adımları**:
1. Yükleme formu üzerinden dosya gönderilir.  
2. Dosya `https://target.com/uploads/shell.php.jpg` altında saklanır.  
3. Saldırgan URL’yi şu şekilde çağırır:  
   `https://target.com/uploads/shell.php.jpg?cmd=id`  
4. Sunucudan komut çıktısı alınır → RCE başarıyla gerçekleşir.  

**Savunma**:
- Uzantıya güvenme → MIME + Magic Byte kontrolü yap.  
- Web root dışında depolama.  
- `Content-Disposition: attachment` ile dosyaların yürütülmesini engelle.  

**Best Practice**:  
Dosya hiçbir koşulda doğrudan çalıştırılabilir formatta saklanmamalı.

---

### 2) HTML / SVG ile XSS

**Senaryo**:  
- Uygulama HTML veya SVG dosya yüklemeye izin veriyor.  
- Saldırgan script içeren bir dosya yükler.  
- Kullanıcı bu dosyayı açtığında XSS tetiklenir.  

**PoC**:  
Dosya adı: `xss.svg`  
İçerik:  
<svg><script>alert('XSS')</script></svg>

**Saldırı Adımları**:
1. Dosya upload edilir.  
2. Kullanıcı dosyayı tarayıcıda açar.  
3. Script çalışır → session hijacking, cookie theft.  

**Savunma**:
- SVG, HTML, XML gibi aktif içerikler engellenmeli.  
- Dosyalar yalnızca indirme modunda sunulmalı (`Content-Disposition: attachment`).  
- CSP (Content Security Policy) aktif olmalı.  

**Best Practice**:  
Kullanıcıya sunulacak dosyalar her zaman pasifleştirilmeli veya dönüştürülmeli.

---

### 3) Path Traversal ile Kritik Dosyaları Ezme

**Senaryo**:  
- Uygulama dosya ismini sanitize etmiyor.  
- Saldırgan `../../.htaccess` gibi bir isimle dosya yükler.  
- Sunucu, önemli dosyaları overwrite eder.  

**PoC**:  
Dosya adı: `../../.htaccess`  
İçerik:  
AddType application/x-httpd-php .jpg

**Saldırı Adımları**:
1. Dosya yüklenir.  
2. `.htaccess` sayesinde `.jpg` dosyaları PHP gibi yorumlanır.  
3. Saldırgan `.jpg` dosyasıyla shell yükleyebilir.  

**Savunma**:
- Dosya isimleri normalize edilmeli.  
- Path traversal girişimleri engellenmeli.  
- Dosya isimleri UUID ile yeniden adlandırılmalı.  

**Best Practice**:  
Kullanıcı tarafından verilen dosya isimleri asla direkt kullanılmamalı.

---

### 4) Polyglot Dosya (Bypass Techniques)

**Senaryo**:  
- Sunucu dosyanın Magic Byte kontrolünü yapıyor ama sadece ilk birkaç byte’a bakıyor.  
- Saldırgan hem resim hem script içeren bir dosya (polyglot) hazırlar.  

**PoC**:  
Dosya başında PNG header, sonunda PHP kodu:  
\x89PNG\r\n\x1a\n  
... (image data) ...  
<?php system($_GET['cmd']); ?>

**Saldırı Adımları**:
1. Dosya `image.png` olarak yüklenir.  
2. Görüntü açıldığında normal görünür.  
3. Sunucu dosyayı çalıştırdığında PHP kodu çalışır.  

**Savunma**:
- Dosyayı yeniden encode et (örneğin PNG → PNG).  
- Yalnızca güvenli formatlara izin ver.  
- İçerik parserları sandbox içinde çalıştırılmalı.  

**Best Practice**:  
Görüntüleri decode → encode pipeline’dan geçirerek polyglot ihtimali ortadan kaldırılmalı.

---

### 5) Büyük Dosya Yükleme (DoS - Disk Dolumu)

**Senaryo**:  
- Dosya boyut limiti uygulanmıyor.  
- Saldırgan çok büyük bir dosya yükler.  
- Disk dolup uygulama çökebilir.  

**PoC**:  
`dd if=/dev/zero of=dos.img bs=1M count=2000`  
(2 GB sahte dosya oluşturulur.)

**Saldırı Adımları**:
1. Dosya yüklenir.  
2. Sunucu depolaması dolana kadar tekrar edilir.  
3. Servis DoS’a uğrar.  

**Savunma**:
- Maksimum dosya boyutu limiti olmalı.  
- Yükleme sırasında **streaming** yaklaşımı kullanılmalı.  
- Disk quota / rate limit uygulanmalı.  

**Best Practice**:  
Tüm dosya yüklemeleri için boyut ve sayı limitleri zorunlu hale getirilmeli.

---

### 6) Metadata Sızıntısı

**Senaryo**:  
- Kullanıcı fotoğraf yükler.  
- EXIF metadata’da GPS koordinatları veya cihaz bilgisi bulunur.  
- Saldırgan bu verileri OSINT için kullanır.  

**PoC**:  
`exiftool photo.jpg`  
→ GPS Location: 41.0, 29.0 (örnek koordinatlar)

**Saldırı Adımları**:
1. Saldırgan yüklenen fotoğrafı indirir.  
2. Metadata’yı inceler.  
3. Kullanıcı konumu / cihaz bilgisi ifşa olur.  

**Savunma**:
- Yüklenen görsellerin metadata bilgileri temizlenmeli.  
- Kullanıcıya sadece temizlenmiş versiyon sunulmalı.  

**Best Practice**:  
`stripMetadata(image)` fonksiyonu pipeline’a eklenmeli.

---

## 🛡️ Genel Savunma Yöntemleri

- **Allowlist** yaklaşımı → yalnızca izin verilen formatlara izin ver.  
- **Web root dışında depolama** → doğrudan erişim engellenmeli.  
- **İçerik taraması** → Magic Byte, MIME, antivirüs.  
- **Yeniden encode** → resim/video gibi dosyaları yeniden işleme.  
- **Başlık güvenliği** → `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment`.  
- **Sandboxlama** → dosya işleme araçları izole ortamda çalıştırılmalı.  
- **Loglama & İzleme** → yükleme denemeleri detaylı loglanmalı.  

---

## 💡 Mülakat Soruları

1. Dosya yükleme açıklarının temel nedenleri nelerdir?  
2. MIME type spoofing nasıl yapılır, nasıl engellenir?  
3. Polyglot dosya nedir, nasıl tespit edilir?  
4. SVG dosyaları neden tehlikeli olabilir?  
5. Web root altında depolama neden risklidir?  
6. Path traversal saldırısı ile dosya yükleme açıkları nasıl birleşebilir?  
7. Metadata sızıntısı güvenlik açısından neden önemlidir?  
8. Dosya yükleme güvenliğinde "defense-in-depth" nasıl uygulanır?  
9. Production ortamında dosya işleme servisleri nasıl izole edilmelidir?  
10. Büyük dosya yüklemelerine karşı hangi önlemler alınmalıdır?

---

## ✅ Sonuç

Dosya yükleme açıkları, modern web uygulamalarında **en kritik saldırı yüzeylerinden biridir**. RCE, XSS, DoS, bilgi sızıntısı gibi farklı etkilere yol açabilir.  
Bir pentester için saldırı senaryolarını bilmek, bir güvenlik mühendisi için ise **savunma katmanlarını** doğru kurgulamak hayati öneme sahiptir.  

📌 Özet: **Dosya yükleme = Güvenlik zincirinin en zayıf halkası olmamalı.**
