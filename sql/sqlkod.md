```md
## 🛡️ SQL Injection Önleme Yöntemleri & Hatalı Kodlar

SQL Injection, web uygulamalarında kullanıcı girdilerinin doğrudan SQL sorgularına eklenmesiyle oluşur.  
Bu bölümde, hangi durumlarda açık ortaya çıkar ve nasıl önlenir detaylı şekilde anlatılmıştır.

---

### 1️⃣ Hatalı Kod Örnekleri (Açık Oluşan Durumlar)
- **Doğrudan kullanıcı girdisi ile sorgu**
```php
// Hatalı PHP kodu
$username = $_GET['user'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);
```
- **Hazırlanmamış veya filtrelenmemiş parametre kullanımı**
```php
$password = $_POST['password'];
$sql = "SELECT * FROM users WHERE password = '$password'";
```
- **Dinamik SQL + string birleştirme**
```python
# Python örneği
query = "SELECT * FROM users WHERE name = '" + input_name + "'"
cursor.execute(query)
```
- **Yorum veya özel karakterlerin filtrelenmemesi**
```
1' OR '1'='1
```

---

### 2️⃣ Açığın Oluştuğu Durumlar
- Kullanıcı girdisi doğrudan sorguya ekleniyor.
- **Prepared Statement veya Parametreli Sorgu** kullanılmıyor.
- Input doğrulama, filtreleme veya tip kontrolü yapılmıyor.
- Hata mesajları açık, detaylı ve veritabanı bilgisi içeriyor.
- Tüm girdi kaynakları kontrol edilmiyor (GET, POST, Cookie, Header).

---

### 3️⃣ Güvenli Kod Örnekleri (Önleme Yöntemleri)
#### a) Prepared Statements / Parametreli Sorgu
```php
// PHP mysqli örneği
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
```
```python
# Python pymysql örneği
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (input_name,))
```

#### b) Input Doğrulama & Filtreleme
- Beklenen tip kontrolü: integer, email, regex
```php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
```

#### c) ORM Kullanımı
- Laravel, Django, SQLAlchemy gibi ORM’ler SQLi riskini minimize eder.
```python
# Django örneği
User.objects.filter(username=input_name)
```

#### d) Hata Mesajlarını Gizleme
- Hata detayları kullanıcıya gösterilmemeli.
```php
ini_set('display_errors', 0);
error_log($e->getMessage());
```

#### e) WAF ve Filtreler
- Kritik alanlar için WAF veya input filtreleri kullanılabilir.
- SQL keyword filtreleme ve özel karakter engelleme.

---

### 4️⃣ Özet Önleme Kuralları
- **Hazırlanmış ifadeler kullan** → Parametreli sorgular.
- **Input kontrolü** → Tip, uzunluk, regex.
- **Hata mesajlarını gizle** → Sunucu ve DB bilgisi sızdırma.
- **ORM veya Framework kullan** → Raw SQL kullanımını azalt.
- **WAF/IPS** → Ek katman olarak düşünebilirsin.
- **Tüm input kaynaklarını denetle** → GET, POST, Cookie, Header.

> SQL Injection’ı önlemek, hem kullanıcı verisini hem sistem bütünlüğünü korur.  
> En kritik adım: **Asla kullanıcı girdisini doğrudan sorguya ekleme.**
```
