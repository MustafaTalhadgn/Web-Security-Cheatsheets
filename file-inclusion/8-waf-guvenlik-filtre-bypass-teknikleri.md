## 📂 File Inclusion 8 - WAF / Güvenlik Filtre Bypass Teknikleri  

File Inclusion zafiyetlerinde güvenlik filtreleri (WAF, IPS, IDS) ve uygulama bazlı input validation mekanizmaları saldırganları engellemeye çalışır. Ancak bazı tekniklerle bu filtreler atlatılabilir.  

---

### 1. URL Encoding  
**Açıklama:**  
- Filtreler genellikle düz metin pattern’lerine bakar.  
- `%2e%2e%2f` (../), `%2f` (/), `%5c` (\) gibi encoding teknikleri ile bypass sağlanabilir.  

**Kod Örneği:**  
http://target.com/index.php?page=..%2f..%2f..%2fetc/passwd  

**Kullanım:**  
- Normal `../` engellense bile encoded hali filtreyi atlatabilir.  

**Sonuç:**  
- Hassas dosyalar okunabilir.  

---

### 2. Double Encoding  
**Açıklama:**  
- Bazı WAF’ler tek katman encoding’i çözer ama ikinci katmanı görmezden gelir.  
- `%252e%252e%252f` = `../`  

**Kod Örneği:**  
http://target.com/index.php?page=%252e%252e%252f%252e%252e%252fetc/passwd  

**Kullanım:**  
- Çift encode edilmiş payload ile filtrelerden kaçılır.  

**Sonuç:**  
- WAF tek seviyeli decoding yapıyorsa, atlatma başarılı olur.  

---

### 3. Wrapper Manipülasyonları  
**Açıklama:**  
- PHP stream wrapper’ları kullanılarak filtreleri aşmak mümkündür.  
- `php://filter`, `php://input`, `data://` gibi wrapper’lar farklı kullanım senaryoları sunar.  

**Kod Örneği:**  
http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config.php  

**Kullanım:**  
- Dosya içeriğini direkt okuma yerine Base64 ile encode ederek WAF atlatılır.  
- `php://input` ile POST body üzerinden zararlı kod enjekte edilebilir.  

**Sonuç:**  
- Hassas dosya içeriği farklı formatta elde edilir.  

---

### 4. Header / Parameter Tampering  
**Açıklama:**  
- Bazı WAF’ler sadece GET parametrelerini kontrol eder.  
- Payload farklı header veya POST parametresi üzerinden gönderilirse bypass edilebilir.  

**Kod Örneği:**  
GET yerine Cookie kullanımı:  
Cookie: page=../../../../etc/passwd  

**Kullanım:**  
- Parametreyi farklı bir HTTP header alanına yerleştirerek filtreyi aşmak.  

**Sonuç:**  
- WAF sadece URL’yi kontrol ediyorsa saldırgan atlatma yapabilir.  

---

### 5. Bypass Senaryoları  
**Senaryo 1:**  
- Normal `../../etc/passwd` engelleniyor.  
- Çözüm: `..%2f..%2fetc/passwd`  

**Senaryo 2:**  
- WAF sadece GET parametresine bakıyor.  
- Çözüm: `POST` body veya `Cookie` içine payload koymak.  

**Senaryo 3:**  
- WAF include edilen dosyanın `.php` uzantısını şart koşuyor.  
- Çözüm: `php://filter` veya `data://` wrapper ile bypass.  

---

📌 **Özet:**  
- **URL Encoding** → Tek katmanlı filtreleri aşar.  
- **Double Encoding** → WAF’in decoding mantığını suistimal eder.  
- **Wrapper Manipülasyonu** → `php://`, `data://` ile alternatif yollar.  
- **Header/Parameter Tampering** → Payload farklı HTTP alanlarından gönderilir.  
- **Bypass Senaryoları** → Filtre mantığına uygun özel teknikler geliştirilir.  
