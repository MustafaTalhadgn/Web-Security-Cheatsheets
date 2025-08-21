## [6-SecLists-ve-Dogru-Wordlist-Secimi](/Brute-Force/6-seclists-ve-dogru-wordlist-secimi.md)  

### 📌 Açıklama  
**SecLists**, Offensive Security topluluğu tarafından GitHub üzerinde yayınlanan, en kapsamlı saldırı amaçlı wordlist koleksiyonlarından biridir.  
İçerisinde şifreler, kullanıcı adları, URL yolları, dizin adları, parametre isimleri gibi birçok farklı kategoriye ait listeler bulunur.  
Doğru wordlist seçimi, brute-force, directory busting ve parola tahmin saldırılarında kritik başarı faktörüdür.  

---

### ⚙ Temel Mantık  
- **SecLists deposu**: https://github.com/danielmiessler/SecLists  
- Klasör yapısı kategoriye göre ayrılmıştır (Passwords, Usernames, Discovery, Fuzzing vb.).  
- Her saldırı senaryosunda farklı wordlist seçilmelidir. Yanlış wordlist kullanımı saldırıyı gereksiz uzatır veya başarısızlığa neden olur.  

---

### 🔎 Kullanılacak Wordlist Kategorileri  

#### 1. **SSH Brute-Force (Kullanıcı adı & Parola)**  
- Kullanıcı adları için:  
  SecLists/Usernames/Names/names.txt  
  SecLists/Usernames/top-usernames-shortlist.txt  
- Parolalar için:  
  SecLists/Passwords/Common-Credentials/10k-most-common.txt  
  SecLists/Passwords/Leaked-Databases/rockyou.txt  

#### 2. **Web Login (Parola & Kullanıcı)**  
- Kullanıcı adları:  
  SecLists/Usernames/top-usernames-shortlist.txt  
  SecLists/Usernames/xato-net-10-million-usernames.txt  
- Parolalar:  
  SecLists/Passwords/Common-Credentials/best1050.txt  
  SecLists/Passwords/darkweb2017-top10000.txt  

#### 3. **URL / Directory Fuzzing (Web keşif)**  
- Dizine karşı fuzzing:  
  SecLists/Discovery/Web-Content/directory-list-2.3-small.txt  
  SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  
- Parametre fuzzing:  
  SecLists/Discovery/Web-Content/burp-parameter-names.txt  
  SecLists/Fuzzing/  

#### 4. **Parola Politikası Testleri (Mutasyon + Zor Parolalar)**  
- SecLists/Passwords/darkc0de.txt  
- SecLists/Passwords/probable-v2-top1575.txt  
- Kurallarla mutasyona uğratılmış RockYou listeleri.  

#### 5. **Spesifik Hizmetlere Yönelik Wordlist’ler**  
- FTP → SecLists/Passwords/FTP/  
- MySQL → SecLists/Passwords/Database/mysql-betterdefaultpasslist.txt  
- Tomcat → SecLists/Passwords/tomcat-betterdefaultpasslist.txt  

---

### 🛠 Kullanım  

- **SecLists klonlama**:  
  git clone https://github.com/danielmiessler/SecLists.git  

- **SSH brute-force Hydra**:  
  hydra -L SecLists/Usernames/top-usernames-shortlist.txt -P SecLists/Passwords/Common-Credentials/10k-most-common.txt 192.168.1.100 ssh  

- **Web login brute-force Hydra**:  
  hydra -L users.txt -P SecLists/Passwords/darkweb2017-top10000.txt http-post-form "/login:username=^USER^&password=^PASS^:Invalid"  

- **Directory fuzzing Gobuster**:  
  gobuster dir -u http://hedefsite.com -w SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  

- **Parametre fuzzing Burp Suite Intruder**:  
  Payload listesi: SecLists/Discovery/Web-Content/burp-parameter-names.txt  

---

### ✅ Sonuç  
- **SecLists**, her saldırı senaryosu için uygun wordlist’i sağlayan güçlü bir koleksiyondur.  
- SSH ve web login için **Usernames + Passwords** klasörleri, dizin keşfi için **Discovery/Web-Content**, parametre denemeleri için **Fuzzing** klasörleri tercih edilmelidir.  
- **Avantaj:** Hazır ve güncel wordlist koleksiyonu.  
- **Dezavantaj:** Çok büyük dosyalar uzun saldırı sürelerine yol açabilir.  

📖 **Özet Not:**  
- SSH → Usernames + Passwords listeleri.  
- Web login → Usernames + darkweb/rockyou listeleri.  
- URL/Directory → Discovery/Web-Content.  
- Parametre → Burp param listeleri.  
- Servis özelinde → ilgili klasör (FTP, MySQL, Tomcat vb.).  
