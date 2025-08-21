## 📂 File Inclusion 9 - Önleme Yöntemleri ve Best Practices  

File Inclusion zafiyetleri, uygulamanın kullanıcı girdisini doğrudan dosya sistemine aktarmasıyla oluşur. Bu zafiyetlerin engellenmesi için güvenlik odaklı geliştirme yöntemleri kullanılmalıdır.  

---

### 1. Input Validation (Girdi Doğrulama)  
**Açıklama:**  
- Kullanıcıdan gelen verilerin doğrudan dosya yolu olarak kullanılmaması gerekir.  
- Sadece belirlenmiş dosyaların yüklenmesine izin verilmelidir.  

**Kod Örneği:**  
$allowed_pages = array("home", "about", "contact");  
if (in_array($_GET['page'], $allowed_pages)) {  
 include($_GET['page'] . ".php");  
} else {  
 echo "Geçersiz sayfa.";  
}  

**Kullanım:**  
- Sadece whitelist içerisinde tanımlı dosyalar çağrılır.  

**Sonuç:**  
- Kullanıcı `../../etc/passwd` gibi payloadlar gönderemez.  

---

### 2. Mutlak Dosya Yolları Kullanma  
**Açıklama:**  
- Göreceli yollar yerine mutlak (absolute) yollar kullanılmalıdır.  
- Böylece `../` gibi traversal saldırıları etkisiz hale gelir.  

**Kod Örneği:**  
$base_path = "/var/www/html/includes/";  
$file = realpath($base_path . $_GET['page'] . ".php");  
if (strpos($file, $base_path) === 0) {  
 include($file);  
} else {  
 echo "Yetkisiz erişim!";  
}  

**Sonuç:**  
- Kullanıcı sadece belirlenen dizin içindeki dosyalara erişebilir.  

---

### 3. Whitelisting vs Blacklisting  
**Açıklama:**  
- Blacklist (yasaklı kelimeler) yaklaşımı bypass edilebilir.  
- Whitelist (izin verilen dosyalar) yaklaşımı güvenlidir.  

**Örnek:**  
- Blacklist: `if (strpos($input, "../") === false) { include($input); }`  
 → Kolayca bypass edilebilir.  
- Whitelist: `if (in_array($input, $allowed)) include($input);`  
 → Daha güvenli.  

**Sonuç:**  
- Daima whitelist mantığı tercih edilmelidir.  

---

### 4. Wrapper’ların Devre Dışı Bırakılması  
**Açıklama:**  
- PHP wrapper’ları (`php://`, `data://`, `expect://`) saldırganlarca kullanılabilir.  
- php.ini ayarlarında gerekli olmayan wrapper’lar kapatılmalıdır.  

**Öneri:**  
allow_url_include = Off  
allow_url_fopen = Off  

**Sonuç:**  
- Uzak dosya yükleme (RFI) riskleri azalır.  

---

### 5. Dosya İzinleri ve Sunucu Yapılandırması  
**Açıklama:**  
- Web sunucusu yalnızca gerekli dosyalara erişim iznine sahip olmalıdır.  
- Config dosyaları webroot dışında tutulmalıdır.  

**Öneriler:**  
- `/etc/passwd` gibi sistem dosyalarına erişim engellenmeli.  
- `.php`, `.ini`, `.env` dosyaları doğru izinlerle korunmalı.  

**Sonuç:**  
- Dosya erişim zafiyetlerinin etkisi minimize edilir.  

---

### 6. Güvenlik Testleri ve Kod Denetimleri  
**Açıklama:**  
- Uygulamalar düzenli olarak güvenlik testlerine tabi tutulmalıdır.  
- Statik kod analizi (SAST) ve dinamik test (DAST) yöntemleri kullanılmalıdır.  

**Sonuç:**  
- Zafiyetler geliştirme aşamasında erken yakalanır.  

---

📌 **Özet Best Practices:**  
- **Whitelist kullanın** → Sadece izin verilen dosyalar çağrılsın.  
- **Mutlak yolları tercih edin** → Traversal saldırıları engellenir.  
- **Wrapper’ları kapatın** → Uzak dosya include riskleri ortadan kalkar.  
- **Dosya izinlerini sıkılaştırın** → Yetkisiz erişim engellenir.  
- **Güvenlik testleri yapın** → Zafiyetler erken tespit edilir.  
