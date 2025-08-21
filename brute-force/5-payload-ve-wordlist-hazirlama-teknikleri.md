## [5-Payload-ve-Wordlist-Hazirlama-Teknikleri](/Brute-Force/5-payload-ve-wordlist-hazirlama-teknikleri.md)  

### 📌 Açıklama  
Brute-force ve parola tahmin saldırılarında kullanılan **payload** ve **wordlist** seçimleri, saldırının başarısını doğrudan etkiler.  
Hazır listeler (RockYou, SecLists) kadar özel (custom) oluşturulan wordlist’ler de kritik rol oynar. Ayrıca parola varyasyon teknikleri ve mutasyon kuralları ile daha güçlü wordlist’ler elde edilir.  

---

### ⚙ Temel Mantık  
- Wordlist = Kullanılacak olası parolaların listesi.  
- Payload = Saldırı aracına gönderilen giriş verileri (örn: Burp Intruder’da kullanıcı adı/parola).  
- Doğru wordlist seçimi, saldırının hızını ve başarı oranını artırır.  
- Mutasyon kuralları (ör. büyük/küçük harf, sonuna yıl ekleme) ile wordlist’ler zenginleştirilir.  

---

### 🔎 Teknikler  

#### 1. **Hazır Wordlist’ler**  
- **RockYou.txt**: En popüler sızdırılmış parola listelerinden biridir (14M+ parola).  
- **SecLists**: GitHub üzerinde barındırılan, kullanıcı adları, parolalar, dizinler, dosya adları gibi geniş kapsamlı bir koleksiyon.  
- Avantaj: Hızlı başlamak için uygundur.  
- Dezavantaj: Hedefe özel olmayabilir.  

#### 2. **Custom Wordlist Oluşturma**  
- Hedef kuruma/kişiye özel bilgilerle hazırlanır.  
- Örn: Şirket adı, çalışan adları, doğum tarihleri, şehirler.  
- **Cewl** gibi araçlarla bir web sitesinden kelime listesi çıkarılabilir.  
- Örnek kullanım:  
  cewl -w hedef.txt -d 2 -m 5 https://hedefsite.com  

#### 3. **Parola Varyasyon Teknikleri**  
- Kelimelere basit eklemeler veya değişiklikler yapılır.  
- Örnekler:  
  - admin → admin123, Admin!, admin2025  
  - parola → p@rola, Parola!, parola1  
- İnsanların sık kullandığı mantıkları taklit eder.  

#### 4. **Mutasyon Kuralları**  
- Otomatik varyasyon üretim teknikleridir.  
- Örnek kurallar:  
  - Harf → sayı/simge (a → @, i → 1, o → 0)  
  - Sonuna yıl ekleme (2023, 2024, 2025)  
  - Baş harfi büyük yapma  
- **Hashcat rules** veya **John the Ripper rules** ile uygulanabilir.  
- Örnek:  
  john --wordlist=rockyou.txt --rules --stdout > mutated.txt  

#### 5. **Kombinasyon (Combinator) Tekniği**  
- İki farklı wordlist birleştirilerek yeni kombinasyonlar üretilir.  
- Örnek:  
  cat isimler.txt soyisimler.txt | combinator.bin > custom.txt  

---

### 🛠 Kullanım  

- **Hydra ile custom wordlist**:  
  hydra -L users.txt -P custom.txt 192.168.1.100 ssh  

- **Burp Suite Intruder payload hazırlama**:  
  - Payload listesi = wordlist.txt  
  - Payload processing:  
    - Prefix: “!”  
    - Suffix: “2025”  
    - Mutations: Case change, URL-encoding  

- **Hashcat ile varyasyon üretme**:  
  hashcat --force -a 0 -r rules/best64.rule hash.txt rockyou.txt  

---

### ✅ Sonuç  
- Doğru wordlist seçimi, brute-force saldırılarında başarı oranını belirleyen en önemli faktördür.  
- Hazır listeler hızlıca işe yarasa da, custom ve mutasyonlu listeler daha hedef odaklıdır.  
- **Avantaj:** Hedefe uyarlanmış wordlist’ler saldırı süresini kısaltır.  
- **Dezavantaj:** Büyük listeler işlem süresini ve tespit riskini artırabilir.  

📖 **Özet Not:**  
- RockYou & SecLists = Başlangıç için ideal.  
- Custom list = Hedef odaklı bilgi ile güçlü.  
- Varyasyonlar = İnsan davranışlarını taklit eder.  
- Mutasyon kuralları = Otomatik kombinasyon üretir.  
- Kombinasyon = Farklı listeleri birleştirerek geniş kapsamlı wordlist.  
