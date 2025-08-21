## [2-Brute-Force Temel Mantığı ve Türleri](/Brute-Force/2-brute-force-temel-mantigi-ve-turleri.md)  

### 📌 Açıklama  
Brute-Force saldırıları, bir sistemin veya servisin güvenlik önlemlerini aşmak için tüm olası giriş kombinasyonlarının denenmesi mantığına dayanır.  
Bu yöntem, saldırganın doğru kullanıcı adı, parola veya şifreleme anahtarını bulana kadar sistematik olarak deneme yapmasını içerir.  

---

### ⚙ Temel Mantık  
- Bir parola belirli bir karakter kümesinden oluşturulmuştur (örn. harfler, rakamlar, semboller).  
- Brute-Force saldırısı bu karakter kümesinden oluşturulabilecek tüm kombinasyonları dener.  
- Doğru kombinasyon bulunduğunda sistem erişime açılır.  

Örnek:  
4 haneli sadece rakamlardan oluşan bir parola = 10.000 ihtimal (0000 - 9999).  
Eğer parola uzunluğu ve karakter kümesi artarsa, brute-force süresi katlanarak artar.  

---

### 🔎 Türleri  

#### 1. **Klasik Brute-Force**  
- Tüm olası kombinasyonlar denenir.  
- Yavaş ama garantili sonuç verir.  

#### 2. **Dictionary Attack (Sözlük Tabanlı Saldırı)**  
- Önceden hazırlanmış parola listeleri kullanılır.  
- Daha hızlıdır fakat parola listedeyse başarılı olabilir.  

#### 3. **Hybrid Attack**  
- Dictionary + Brute-Force karışımıdır.  
- Örn: "admin123", "password2025" gibi popüler parolaların varyasyonlarını dener.  

#### 4. **Reverse Brute-Force**  
- Tek bir parola birçok kullanıcı hesabı üzerinde denenir.  
- Özellikle ortak kullanılan parolaları hedefler.  

#### 5. **Credential Stuffing**  
- Daha önce sızdırılmış kullanıcı adı-parola kombinasyonları farklı sistemlerde denenir.  
- Günümüzde en yaygın yöntemlerden biridir.  

---

### 🛠 Kullanım  
Örnek Hydra komutu ile SSH brute-force:  
hydra -l root -P wordlist.txt 192.168.1.100 ssh  

Örnek Burp Suite Intruder senaryosu:  
- Hedef: `/login` endpoint  
- Payload: `username=admin&password=^PASS^`  
- Wordlist: `rockyou.txt`  

---

### ✅ Sonuç  
- Brute-Force saldırıları basit ama güçlü bir mantığa dayanır.  
- Türleri sayesinde farklı senaryolara uyarlanabilir.  
- **Avantaj:** Kesin başarı ihtimali vardır.  
- **Dezavantaj:** Uzun sürebilir ve güvenlik sistemlerince kolayca tespit edilebilir.  

📖 **Özet Not:**  
- Klasik brute-force = Tüm ihtimaller.  
- Dictionary = Hazır listeler.  
- Hybrid = Liste + varyasyonlar.  
- Reverse brute-force = Tek parola, çok hesap.  
- Credential stuffing = Sızdırılmış bilgilerle giriş denemesi.  
