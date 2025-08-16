## 📌 Dosya Yükleme Açık Türleri

Dosya yükleme mekanizmasında farklı seviyelerde güvenlik açıkları görülebilir. Bu açık türleri, saldırganın sisteme yüklediği dosyayı **nasıl istismar edebileceğini** ve **hangi güvenlik katmanının eksik olduğunu** gösterir. Bir pentester için bu kategorileri bilmek, test sırasında doğru senaryoları denemek açısından kritik öneme sahiptir.

---

### 1) Uzantı Kontrolü Atlatma (Extension Bypass)

- **Açıklama**: Uygulama yalnızca dosya uzantısını kontrol ediyorsa, saldırgan uzantıyı değiştirerek veya gizleyerek yüklemeyi atlatabilir.
- **Yöntemler**:
  - Çift uzantı: `shell.php.jpg`
  - Büyük/küçük harf: `SHELL.PHP`
  - Nokta ekleme: `shell.php.`
  - Unicode/Null byte: `shell.php%00.jpg`
- **Risk**: Script dosyası yüklenip çalıştırılabilir.

---

### 2) MIME Type Manipülasyonu

- **Açıklama**: Sunucu, `Content-Type` başlığına güvenirse saldırgan sahte MIME ile zararlı dosya gönderebilir.
- **Yöntemler**:
  - `Content-Type: image/png` başlığı ile aslında PHP dosyası yüklemek.
- **Risk**: Dosya uzantı kontrolünden geçer ama içerik yürütülebilir olur.

---

### 3) Magic Byte / İçerik Doğrulama Eksikliği

- **Açıklama**: Dosya içerik kontrolü yapılmazsa saldırgan, polyglot veya sahte başlık içeren dosya yükleyebilir.
- **Örnek**:
  - İlk birkaç byte’ı PNG gibi görünen ama içinde PHP kodu olan dosya.
- **Risk**: Hem yüklenebilir hem de yürütülebilir içerik.

---

### 4) Web Root İçinde Depolama

- **Açıklama**: Dosyalar doğrudan web kökü (`/var/www/html/uploads/`) içine kaydediliyorsa saldırgan dosyayı URL üzerinden çağırabilir.
- **Risk**: Yürütülebilir script dosyaları direkt çalıştırılabilir, HTML/JS ile XSS veya phishing yapılabilir.

---

### 5) Path Traversal ile Dosya Manipülasyonu

- **Açıklama**: Dosya adı sanitize edilmezse, saldırgan `../../` dizin geçişi yaparak sistemde kritik dosyaları ezebilir veya erişebilir.
- **Örnek**:
  - `../../.htaccess` yükleyerek sunucu davranışını değiştirme.
  - `../../config.php` üzerine yazma.
- **Risk**: Sunucu yapılandırmasının ele geçirilmesi.

---

### 6) Overwrite (Mevcut Dosyaların Ezilmesi)

- **Açıklama**: Rastgele isimlendirme yoksa, saldırgan aynı isimde dosya yükleyerek mevcut kritik dosyaları ezebilir.
- **Örnek**:
  - `logo.png` yerine zararlı `logo.png` yüklemek.
- **Risk**: Kullanıcıya sunulan dosyaların bozulması veya zararlı hale gelmesi.

---

### 7) Polyglot Dosyalar

- **Açıklama**: Dosya birden fazla formatta geçerli olacak şekilde hazırlanabilir (örn. hem resim hem script).
- **Örnek**:
  - Hem JPEG hem de PHP olarak çalışan bir dosya.
- **Risk**: İçerik taramasını atlatır, yükleme sonrası çalıştırılabilir hale gelir.

---

### 8) Aktif İçerik Yükleme (SVG, PDF, Office)

- **Açıklama**: Güvenli sanılan ama aslında script/makro çalıştırabilen dosyalar.
- **Örnekler**:
  - **SVG** → `<script>` ile XSS.
  - **PDF** → JavaScript veya gömülü zararlı içerik.
  - **Office** → Makro tabanlı zararlı.
- **Risk**: Kullanıcı taraflı saldırılar, kimlik avı, zararlı yayılımı.

---

### 9) Büyük Dosya / Çoklu Yükleme (DoS)

- **Açıklama**: Boyut sınırlaması yoksa saldırgan çok büyük dosya yükleyerek depolama veya işlemciyi tüketebilir.
- **Risk**: Disk dolumu, bellek taşması, uygulama çökmesi.

---

### 10) Metadata / EXIF Sızıntıları

- **Açıklama**: Resim ve belge dosyaları EXIF/IPTC/XMP gibi metadata içerir. Bunlar temizlenmezse hassas bilgiler (kullanıcı adı, konum, yazılım sürümü) sızabilir.
- **Risk**: Bilgi toplama (OSINT), hedefli saldırılara hazırlık.

---

### 11) Dosya İşleyici (Pipeline) Açıkları

- **Açıklama**: Thumbnailer, dönüştürücü (ImageMagick, LibreOffice, FFMPEG vb.) dosyayı işlerken parser bug’ları tetiklenebilir.
- **Örnek**: ImageTragick (CVE-2016-3714).
- **Risk**: Dosya işleme sırasında RCE.

---

### 12) İşyükü / İş Mantığı Kusurları

- **Açıklama**: Yükleme sonrası onay mekanizmalarının atlanması, rol kontrollerinin zayıf olması.
- **Örnek**:
  - Kullanıcı normalde sadece profil resmi yükleyebilirken API açıkları nedeniyle zararlı dosya da yükleyebiliyor.
- **Risk**: Yetkisiz dosya yükleme → RCE veya veri sızıntısı.

---

## 🧪 Kullanım

Pentester, bu açık türlerini test ederken:  
1. **Uzantı/MIME manipülasyonu** ile bypass denemeleri yapmalı.  
2. **Polyglot** dosyalarla güvenlik kontrollerini test etmeli.  
3. **Depolama konumunu** incelemeli → web root mu, özel klasör mü.  
4. **Path traversal/overwrite** girişimleri ile dosya kontrolünü test etmeli.  
5. **Aktif formatların (SVG/PDF/Office)** filtrelenip filtrelenmediğini kontrol etmeli.  
6. **Büyük boyutlu yüklemeler** ile DoS dayanıklılığı test edilmeli.  
7. **İşleme pipeline** (thumbnailer, convert) güvenliğini denemeli.  

---

## 🎯 Sonuç

Dosya yükleme açık türleri, sadece uzantı veya MIME kontrolüyle sınırlandırılamaz. Pentester için kritik olan:  
- **Hangi katmanın eksik olduğunu** bulmak.  
- **Hangi bypass tekniğinin** başarılı olduğunu göstermek.  
- **Riskin etkisini** (RCE, XSS, DoS, bilgi sızıntısı) net şekilde raporlamaktır.  

📌 **Unutma:** Dosya yükleme açıkları çoğu zaman **zincirleme saldırılarla birleşir** (XSS + CSRF, Path Traversal + LFI, Pipeline RCE vb.) ve etki katlanarak artar.
