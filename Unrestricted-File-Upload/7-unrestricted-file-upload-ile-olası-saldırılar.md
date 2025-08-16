# 🚨 Unrestricted File Upload ile Olası Saldırılar

Unrestricted File Upload zafiyetleri, bir web uygulamasında kullanıcı tarafından yüklenen dosyaların **yetersiz doğrulama ve kontrol** ile sisteme kabul edilmesi sonucu oluşur. Bu açıklık, saldırganlara çok çeşitli saldırı yüzeyleri sunar: RCE, XSS, DoS, Malware dağıtımı ve bilgi sızdırma gibi.

---

## 📌 1. Remote Code Execution (RCE)

**Açıklama:**  
Saldırgan, sunucu tarafından çalıştırılabilen bir script yükleyerek sistem üzerinde uzaktan komut çalıştırabilir.

**PoC Örneği:**  
Dosya adı: `shell.php.jpg`  
İçerik:
<?php system($_GET['cmd']); ?>

**Saldırı Adımları:**  
1. File upload formundan `shell.php.jpg` yüklenir.  
2. Sunucu dosyayı web root altında kaydeder.  
3. Saldırgan URL’yi çağırır: `http://target.com/uploads/shell.php.jpg?cmd=whoami`  
4. Komut çıktısı alınır → RCE gerçekleşir.  

**Savunma:**  
- Web root dışında dosya depolama.  
- MIME ve Magic Byte doğrulaması.  
- Script dosyalarını engelleme.  

---

## 📌 2. Cross-Site Scripting (XSS)

**Açıklama:**  
Saldırgan, `.html` veya `.svg` dosyaları yükleyerek kullanıcı tarayıcısında zararlı script çalıştırabilir.

**PoC Örneği:**  
Dosya adı: `attack.svg`  
İçerik:
<svg onload=alert('XSS')>

**Saldırı Adımları:**  
1. Dosya yüklenir ve kullanıcıya sunulur.  
2. Tarayıcı dosyayı açar.  
3. Script çalışır → session hijacking veya phishing yapılabilir.  

**Savunma:**  
- Aktif içerikli dosyaları engelleme.  
- Content-Disposition: attachment header kullanımı.  
- CSP (Content Security Policy) uygulanması.  

---

## 📌 3. Path Traversal ve Overwrite

**Açıklama:**  
Dosya isimleri sanitize edilmezse, saldırgan sunucudaki kritik dosyaları **overwrite** edebilir veya dizinler arasında gezinerek zararlı dosya yerleştirebilir.

**PoC Örneği:**  
Dosya adı: `../../.htaccess`  
İçerik:
AddType application/x-httpd-php .jpg

**Saldırı Adımları:**  
1. Dosya yüklenir.  
2. Web root altındaki `.htaccess` dosyası değiştirilir.  
3. Artık `.jpg` dosyaları PHP gibi çalıştırılabilir.  

**Savunma:**  
- Dosya isimlerini sanitize et.  
- Rastgele UUID ile yeniden adlandır.  
- Path traversal girişimlerini engelle.  

---

## 📌 4. Polyglot Dosyalar

**Açıklama:**  
Polyglot dosyalar, hem geçerli bir formatta (JPEG, PNG) hem de script içerebilir. Dosya içerik taramasını atlatabilir.

**PoC Örneği:**  
Dosya başı: JPEG header  
Dosya sonu: <?php system($_GET['cmd']); ?>

**Saldırı Adımları:**  
1. Polyglot dosya yüklenir.  
2. Görünüşte masum dosya → sunucu tarafından çalıştırılabilir script.  

**Savunma:**  
- Dosyayı decode → encode pipeline’dan geçir.  
- İçerik taramasını sunucu tarafında uygula.  

---

## 📌 5. DoS (Denial of Service)

**Açıklama:**  
Saldırgan çok büyük boyutlu dosya yükleyerek sunucunun disk veya bellek kaynaklarını tüketebilir.

**PoC Örneği:**  
`dd if=/dev/zero of=largefile.img bs=1M count=2048` (2 GB dosya)

**Saldırı Adımları:**  
1. Büyük dosya yüklenir.  
2. Disk alanı dolar, sunucu veya uygulama hizmet veremez.  

**Savunma:**  
- Maksimum dosya boyutu limiti (örn: 2MB) uygula.  
- Rate limiting ile yükleme sayısını sınırla.  
- Dosya boyutu loglaması ve uyarı mekanizması kur.  

---

## 📌 6. Malware ve Trojan Dağıtımı

**Açıklama:**  
Saldırgan zararlı yazılımları `.exe`, `.pdf` veya `.doc` formatında yükleyebilir. Kullanıcılar dosyayı açtığında malware çalışır.

**PoC Örneği:**  
- `invoice.pdf` içine gömülü RAT (Remote Access Trojan)  
- `setup.exe` → trojanized installer  

**Savunma:**  
- Dosya taraması (antivirus / sandbox)  
- Kullanıcıya sadece güvenli Content-Disposition ile sunum  

---

## 🛡️ Savunma Yöntemleri (Best Practices)

1. **Whitelist** yaklaşımı → sadece izin verilen formatlar.  
2. **MIME ve Magic Byte kontrolü** → dosya içeriği doğrulama.  
3. **Upload dizini izole** → web root dışında depola.  
4. **Random filename** → kullanıcı isimlerini kullanma.  
5. **Antivirus ve sandbox tarama**.  
6. **Loglama ve SIEM entegrasyonu** → şüpheli aktiviteleri tespit et.  
7. **WAF kuralları** → zararlı payload’ları filtrele.  

---

## 💡 Mülakat Soruları

1. File upload açığı ile RCE nasıl elde edilir?  
2. Polyglot dosya nedir ve nasıl tespit edilir?  
3. Path traversal ile dosya yükleme saldırısı nasıl yapılır?  
4. Büyük dosya yükleme (DoS) nasıl önlenir?  
5. XSS ve phishing payload’ları dosya yükleme üzerinden nasıl çalıştırılır?  
6. Dosya upload güvenliğinde en kritik üç önlem nedir?  
7. Malware dağıtımı için file upload nasıl istismar edilebilir?  

---

## ✅ Sonuç

Unrestricted File Upload zafiyetleri, saldırganlara **çok yönlü saldırı imkanı** sunar.  
RCE, XSS, DoS, Malware ve bilgi sızıntısı riskleri bulunmaktadır.  
Pentester ve güvenlik uzmanları için kritik öncelik, **hem tespit hem de savunma** mekanizmalarını eksiksiz uygulamaktır.  
