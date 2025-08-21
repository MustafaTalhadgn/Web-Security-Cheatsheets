## [6-Temel-Saldiri-Senaryolari-ve-Uygulamalar](/Brute-Force/6-temel-saldiri-senaryolari-ve-uygulamalar.md)  

### 📌 Açıklama  
Siber güvenlikte brute-force ve parola saldırıları farklı senaryolara göre uygulanır. Bu senaryolarda **hazır wordlist’ler (RockYou, SecLists)**, **custom wordlist’ler**, **parola varyasyon teknikleri** ve **mutasyon kuralları** kritik rol oynar.  
Her saldırı senaryosunda doğru araç + doğru wordlist seçimi başarı oranını doğrudan belirler.  

---

### ⚙ Temel Mantık  
- Hazır listeler (örn. RockYou, SecLists) başlangıç için kullanılır.  
- Custom wordlist = Hedefe özgü bilgilerden oluşturulan liste.  
- Parola varyasyonları = İnsanların sık kullandığı parolaların basit değişimleri.  
- Mutasyon kuralları = Otomatik olarak varyasyon üretme (örn. Hashcat, John the Ripper).  
- Senaryolar: SSH brute-force, Web login brute-force, Directory fuzzing, Credential stuffing vb.  

---

### 🔎 Temel Saldırı Senaryoları  

#### 1. **SSH Brute-Force**  
- Amaç: Sunucuya yetkisiz erişim sağlamak.  
- Kullanıcı adı listesi: SecLists/Usernames/top-usernames-shortlist.txt  
- Parola listesi: SecLists/Passwords/Common-Credentials/10k-most-common.txt  
- Örnek Hydra komutu:  
  hydra -L usernames.txt -P rockyou.txt 192.168.1.100 ssh  

#### 2. **Web Login Brute-Force**  
- Amaç: Web uygulaması giriş ekranındaki kullanıcı/parolayı tahmin etmek.  
- Kullanıcı adları: SecLists/Usernames/top-usernames-shortlist.txt  
- Parolalar: RockYou veya SecLists/Passwords/darkweb2017-top10000.txt  
- Örnek Hydra POST isteği:  
  hydra -L users.txt -P passwords.txt hedefsite.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"  

#### 3. **Directory & URL Fuzzing**  
- Amaç: Gizli dizinleri ve dosyaları keşfetmek.  
- Wordlist: SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  
- Örnek Gobuster:  
  gobuster dir -u http://hedefsite.com -w directory-list-2.3-medium.txt  

#### 4. **Custom Wordlist Kullanımı**  
- Hedef odaklı liste: Çalışan isimleri, şirket bilgileri, doğum tarihleri.  
- Cewl aracıyla web sitesinden liste oluşturma:  
  cewl -w hedef.txt -d 2 -m 5 https://hedefsite.com  

#### 5. **Parola Varyasyonları & Mutasyon Kuralları**  
- Örnek: admin → Admin123, admin!, adm1n2025  
- Hashcat rules kullanımı:  
  hashcat --force -a 0 -r rules/best64.rule hash.txt rockyou.txt  
- John the Ripper rules ile varyasyon üretimi:  
  john --wordlist=rockyou.txt --rules --stdout > mutated.txt  

#### 6. **Credential Stuffing**  
- Daha önce sızdırılmış kullanıcı adı/parola kombinasyonlarını kullanma.  
- Kaynak: HaveIBeenPwned dump’ları veya SecLists/Passwords/Leaked-Databases klasörü.  
- Avantaj: Daha hızlı sonuç alınabilir çünkü gerçek dump verileri kullanılır.  

---

### 🛠 Kullanım  

- SSH için Hydra:  
  hydra -L SecLists/Usernames/top-usernames-shortlist.txt -P SecLists/Passwords/Common-Credentials/10k-most-common.txt 192.168.1.100 ssh  

- Web login brute-force:  
  hydra -L users.txt -P rockyou.txt hedefsite.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"  

- Directory keşfi Gobuster:  
  gobuster dir -u http://hedefsite.com -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt  

- Custom wordlist üretimi Cewl:  
  cewl -w hedef.txt -d 2 https://hedefsite.com  

- Mutasyon kuralı John:  
  john --wordlist=rockyou.txt --rules --stdout > mutated.txt  

---

### ✅ Sonuç  
- Brute-force saldırıları farklı senaryolara uyarlanabilir: SSH, web login, directory keşfi, credential stuffing.  
- **RockYou & SecLists** hızlı başlangıç için uygundur.  
- **Custom wordlist** + **varyasyon teknikleri** hedef odaklı başarı oranını artırır.  
- **Mutasyon kuralları** ile otomatik varyasyon üretmek, saldırının gücünü katlar.  
- **Avantaj:** Esneklik ve yüksek başarı ihtimali.  
- **Dezavantaj:** Büyük listeler işlem süresini ve tespit riskini artırır.  

📖 **Özet Not:**  
- SSH → Usernames + Passwords listeleri.  
- Web login → RockYou + darkweb listeleri.  
- Directory fuzzing → Discovery/Web-Content listeleri.  
- Custom wordlist → Hedefe özel bilgiler.  
- Mutasyon kuralları → Parola varyasyonları.  
- Credential stuffing → Sızdırılmış gerçek parolalar.  
