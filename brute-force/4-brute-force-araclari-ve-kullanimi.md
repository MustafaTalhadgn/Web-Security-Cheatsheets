## [4-Brute-Force Araçları ve Kullanımı](/Brute-Force/4-brute-force-araclari-ve-kullanimi.md)  

### 📌 Açıklama  
Brute-Force saldırıları manuel olarak yapılabilecek olsa da, modern dünyada bu saldırıları otomatikleştiren birçok araç geliştirilmiştir.  
Bu araçlar, büyük parola listelerini kullanarak hedef sisteme hızlı ve sistematik giriş denemeleri yapar.  
Her aracın farklı protokol ve senaryolar için özel yetenekleri vardır.  

---

### 🔧 Yaygın Brute-Force Araçları  

#### 1. **Hydra**  
- Çok hızlı ve popüler brute-force aracıdır.  
- FTP, SSH, Telnet, HTTP, RDP gibi birçok protokolü destekler.  

**Örnek Kullanım:**  
hydra -l admin -P rockyou.txt ftp://192.168.1.100  
hydra -L users.txt -P passwords.txt ssh://192.168.1.101  

---

#### 2. **Medusa**  
- Hydra’ya benzer, hız odaklı bir araçtır.  
- Modüler yapısı sayesinde çok çeşitli servislerde kullanılabilir.  

**Örnek Kullanım:**  
medusa -h 192.168.1.100 -u admin -P wordlist.txt -M ssh  

---

#### 3. **Ncrack**  
- Ağ servisleri üzerinde brute-force saldırıları için geliştirilmiştir.  
- Özellikle RDP, SSH, FTP gibi servislerde etkilidir.  

**Örnek Kullanım:**  
ncrack -p 22,21,3389 192.168.1.105  
ncrack -U users.txt -P passwords.txt rdp://192.168.1.110  

---

#### 4. **John the Ripper**  
- Daha çok parola hash kırma amacıyla kullanılır.  
- Sızdırılmış hash verileri üzerinde brute-force ve sözlük saldırıları yapar.  

**Örnek Kullanım:**  
john --wordlist=rockyou.txt hashes.txt  
john --incremental hashes.txt  

---

#### 5. **Burp Suite Intruder**  
- Web uygulamaları için güçlü bir brute-force aracıdır.  
- Parametre brute-force, kullanıcı adı/parola testleri yapılabilir.  

**Örnek Kullanım:**  
- Login formundaki "password" parametresini seç.  
- Payload listesi olarak wordlist.txt dosyasını yükle.  
- Sonuçları analiz ederek geçerli parolayı bul.  

---

#### 6. **Aircrack-ng**  
- Kablosuz ağ şifrelerini brute-force etmek için kullanılır.  
- WPA/WPA2 saldırılarında sıkça tercih edilir.  

**Örnek Kullanım:**  
aircrack-ng -w rockyou.txt capture.cap  

---

### 🛠 Kullanım  

**Temel Adımlar:**  
1. Hedef belirlenir (IP, domain veya servis).  
2. Kullanıcı adı veya kullanıcı listesi elde edilir.  
3. Parola listesi (wordlist) hazırlanır.  
4. Uygun araç seçilerek saldırı başlatılır.  
5. Sonuçlar analiz edilir.  

---

### ✅ Sonuç  
- Brute-Force araçları saldırıyı otomatikleştirir ve hızlandırır.  
- Hydra, Medusa ve Ncrack ağ servisleri için; John the Ripper hash kırma için; Burp Suite Intruder web uygulamaları için; Aircrack-ng kablosuz ağlar için en popüler seçeneklerdir.  
- Doğru araç ve doğru wordlist ile saldırının başarı şansı artar.  
- Ancak brute-force saldırıları genellikle çok gürültülüdür ve güvenlik sistemleri tarafından tespit edilme olasılığı yüksektir.  

📖 **Özet Not:**  
- Araçlar: Hydra, Medusa, Ncrack, John the Ripper, Burp Suite Intruder, Aircrack-ng  
- Kullanım: Hedef seç, kullanıcı/parola listesi hazırla, uygun aracı çalıştır  
- Sonuç: Otomasyon → hız, kolaylık; fakat tespit edilme riski yüksek  
