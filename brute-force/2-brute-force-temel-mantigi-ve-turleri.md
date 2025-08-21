## [1-Giriş](/Brute-Force/1-giris.md)  

### 📌 Açıklama  
Brute-Force saldırısı, bir sistemin parola veya şifreleme mekanizmasını çözmek için tüm olası kombinasyonların sistematik olarak denenmesi yöntemidir. Basit ve ilkel görünmesine rağmen, özellikle zayıf parolalara sahip sistemler üzerinde hala etkili bir saldırı türüdür.  

---

### 📖 Tarihçe  
- İlk Brute-Force saldırıları bilgisayarların henüz yavaş olduğu dönemlerde bile uygulanmıştır.  
- Kriptografi alanında, klasik şifreleme algoritmalarını çözmek için en temel yöntemlerden biri olmuştur.  
- Modern dönemde güçlü bilgisayarların, GPU’ların ve botnet’lerin kullanılmasıyla hız kazanmıştır.  

---

### 🔎 Kullanım Alanları  
- **Parola Kırma:** Kullanıcı hesaplarının parolalarının tahmin edilmesi.  
- **Kriptografi:** Şifreli metinlerin anahtarlarının denenmesi.  
- **Web Uygulamaları:** Login formları, admin panelleri üzerinde deneme-yanılma yoluyla giriş sağlama.  
- **Ağ Protokolleri:** FTP, SSH, RDP gibi servislerde brute-force ile kimlik doğrulama kırılması.  

---

### ⚔ Diğer Saldırı Yöntemlerinden Farkları  
- **Dictionary Attack:** Önceden hazırlanmış parola listesi kullanılır.  
- **Brute-Force:** Tüm olasılıklar denenir, daha uzun sürer ama daha garantilidir.  
- **Hybrid Attack:** Dictionary + Brute-Force kombinasyonu.  
- **Credential Stuffing:** Daha önce sızdırılmış kullanıcı-parola kombinasyonlarının denenmesi.  

---

### 🛠 Kullanım  
Örnek bir brute-force senaryosu:  

- Kullanıcı giriş formunda `username` ve `password` parametreleri vardır.  
- Saldırgan, otomatik araçlar (Hydra, Burp Suite Intruder, Medusa, Ncrack vb.) kullanarak binlerce farklı parola dener.  

Komut örneği (Hydra):  
hydra -l admin -P passwords.txt 192.168.1.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Hatalı giriş"  

---

### ✅ Sonuç  
- Brute-Force saldırıları özellikle zayıf parola politikası olan sistemlerde ciddi risk oluşturur.  
- Daha gelişmiş yöntemlere göre basit ama etkili olabilir.  
- **Avantaj:** Kesinlikle doğru parolayı bulma ihtimali vardır.  
- **Dezavantaj:** Çok uzun sürebilir ve genellikle IDS/IPS sistemlerince tespit edilebilir.  

📖 **Özet Not:**  
- Brute-Force = Tüm ihtimallerin denenmesi.  
- Etkili olduğu durum = Zayıf parola kullanımı.  
- Önleme = Güçlü parola politikaları, 2FA, rate limiting, CAPTCHA.  
