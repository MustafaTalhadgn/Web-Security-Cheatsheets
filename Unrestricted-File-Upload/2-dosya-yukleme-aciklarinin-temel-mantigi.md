## 🧩 Dosya Yükleme Açıklarının Temel Mantığı

Dosya yükleme açıklarının temel mantığı, **kullanıcının yüklediği dosyanın yeterince kontrol edilmeden sunucuya kabul edilmesi ve işlenmesi** durumudur. Bu zafiyet, web uygulamalarında çok sık karşılaşılan ve istismar edildiğinde doğrudan **sistem ele geçirme (RCE)** veya **kullanıcıların hedef alınması (XSS, phishing, malware)** gibi ciddi sonuçlar doğuran bir güvenlik problemidir.

---

### 1) Güvenli Bir Dosya Yükleme Süreci Nasıl Olmalı?

Normal şartlarda dosya yükleme mekanizması aşağıdaki adımlarla güvenli hâle getirilebilir:

1. **Dosya uzantısının kontrol edilmesi**  
   - Yalnızca iş gereği desteklenen türler: `.jpg`, `.png`, `.pdf` gibi.  
   - Uzantı tek başına güvenlik sağlamaz; sadece ilk bariyer olmalıdır.

2. **MIME Type kontrolü (Content-Type doğrulaması)**  
   - Hem istemci (tarayıcı) hem de sunucu tarafında doğrulama yapılmalı.  
   - Sunucu, `Content-Type` başlığına değil, **gerçek dosya içeriğine** güvenmelidir.  

3. **Dosya boyut sınırının uygulanması**  
   - Örn. maksimum 2–5 MB.  
   - Çok büyük yüklemeler disk dolumuna ve **DoS saldırılarına** yol açabilir.  

4. **Güvenli depolama dizini**  
   - Dosyalar **web root dışında** tutulmalı.  
   - Kullanıcıya sunum, imzalı linkler veya proxy üzerinden yapılmalı.  

5. **Dosya isminin sanitize edilmesi**  
   - Özel karakterler, boşluklar, unicode manipülasyonları temizlenmeli.  
   - Rastgele UUID/Hash isimlendirme yapılmalı.  

6. **Dosyanın içeriğinin analiz edilmesi**  
   - Antivirüs/ICAP taraması.  
   - Metadata temizleme (örn. EXIF/IPTC/XMP).  
   - Aktif içeriklerden arındırma (SVG → PNG rasterize, PDF flatten vb.).

---

### 2) Uygulamalarda Sık Görülen Zayıflıklar

Ne yazık ki pratikte bu adımların çoğu atlanır. En yaygın hatalar:

- **Sadece uzantı kontrolü yapılması**  
  `.php.png` gibi çift uzantılı dosyalarla saldırgan yükleme yapabilir.  

- **MIME type doğrulamasının sadece istemci tarafında bırakılması**  
  Tarayıcıdan gönderilen `Content-Type: image/png` başlığı kolayca sahte olabilir.  

- **Web root altında depolama**  
  Yüklenen dosya doğrudan `https://site.com/uploads/file.php` gibi çağrılabilir.  
  → Eğer dosya yürütülebilir kod içeriyorsa RCE kaçınılmazdır.  

- **Dosya isimlerinin kontrol edilmemesi**  
  Path traversal (`../../`) veya overwrite ile kritik dosyalar ezilebilir.  
  Örn. `.htaccess`, `.env`, `index.php` gibi.  

- **Boyut limitlerinin olmaması**  
  Saldırgan çok büyük dosyalar yükleyerek diski doldurabilir (**DoS**).  

- **Aktif içeriklerin (SVG, PDF, Office, HTML) güvenli sanılması**  
  Oysa bu formatlar script, makro veya embedded içerik barındırabilir.  

---

### 3) Saldırganın Yapabilecekleri

- **Script dosyaları yükleme**  
  `.php`, `.asp`, `.jsp`, `.aspx` → web shell ile **uzaktan komut çalıştırma**.  

- **HTML/JS dosyaları barındırma**  
  → **XSS**, phishing sayfaları, token çalma.  

- **Polyglot dosyalar**  
  Aynı anda hem resim hem script çalıştıran özel dosyalar.  

- **DoS saldırısı**  
  Büyük boyutlu veya çok sayıda dosya ile depolama ve işlemci tüketimi.  

- **Overwrite ve Path Traversal**  
  Kritik sistem dosyalarını ezerek veya gizli dosyalara erişerek kontrol kazanma.  

---

### 4) Örnek Güvensiz Senaryo (Psödokod)

function uploadFile(request):
    file = request.file
    savePath = "/var/www/html/uploads/" + file.name
    writeFile(savePath, file.content)
    return "Yüklendi: " + savePath

- Dosya `uploads/` altında **doğrudan erişilebilir**.  
- `file.name` sanitize edilmemiş → path traversal / overwrite riski.  
- MIME veya içerik doğrulaması yok → `.php` yüklenirse direkt çalışır.  

Sonuç: Tek satırlık bir web shell yüklenir, ardından sunucu tamamen ele geçirilebilir.

---

### 5) Örnek Güvenli Senaryo (Psödokod)

function secureUpload(request):
    file = request.file
    
    # 1. Boyut sınırı
    if file.size > MAX_SIZE:
        return "Hata: Dosya çok büyük"
    
    # 2. Uzantı ve MIME kontrolü
    if not isAllowedExtension(file.name) or not isValidMime(file.content):
        return "Hata: İzin verilmeyen dosya türü"
    
    # 3. İsim rastgeleleştirme
    safeName = generateUUID() + getSafeExtension(file.name)
    
    # 4. Web root dışında güvenli depolama
    savePath = "/var/storage/uploads/" + safeName
    writeFile(savePath, file.content)
    
    # 5. Antivirüs / içerik taraması
    if scanFile(savePath) == "malicious":
        deleteFile(savePath)
        return "Hata: Zararlı içerik"
    
    return "Yükleme başarılı"

---

### 6) Sonuç

Dosya yükleme açıklarının temel mantığı:  
- **Yetersiz input validation** (uzantı, MIME, içerik doğrulaması yapılmaması)  
- **Insecure file handling** (web root altında kaydetme, isim kontrolü eksikliği)  

Bir uygulama yalnızca uzantıya güvenirse, saldırgan kolayca filtreyi aşar.  
Bir uygulama dosyayı web root altında tutarsa, saldırgan o dosyayı çalıştırır.  

📌 **Kısacası:** Dosya yükleme güvenliği, yalnızca “uzantı kontrolü” değil;  
**uzantı + MIME + içerik analizi + güvenli depolama + güvenli sunum** katmanlarının tamamının uygulanmasıyla sağlanır.  

