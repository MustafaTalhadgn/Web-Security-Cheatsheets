# 📂 Unrestricted File Upload Rehberi (2025) — Giriş ve Önemli Notlar

> Bu repo, web uygulamalarında dosya yükleme yüzeyinin güvenli tasarımı, uygulaması ve test edilmesi için pratik, savunma-odaklı bir rehberdir. Amaç; **kırmızı ekiplerin istismar mantığını anlamak**, **mavi ekiplerin ise etkili önleyici kontrolleri** hayata geçirmesini sağlamaktır.

---

## 1) Giriş

**Unrestricted File Upload (Sınırsız Dosya Yükleme)**; kullanıcıların yüklediği dosyaların türü, içeriği, boyutu, meta verisi, saklandığı yer ve erişim biçimi gibi kritik parametrelerin **yetersiz doğrulanması** sonucunda ortaya çıkan, sıklıkla **uzaktan komut çalıştırma (RCE)** ve **kalıcı ele geçirme** ile sonuçlanabilen **kritik** bir güvenlik zafiyetidir.

### 1.1 Neden Kritik?
- **Kod yürütme ve kalıcı arka kapı**: Yürütülebilir içeriklerin (ör. sunucu tarafında yorumlanan betikler) web köküne düşmesi veya yanlış işleyen dönüşüm/thumbnail servisleri üzerinden RCE.
- **XSS/HTML injection**: SVG, HTML, MarkDown, XML, PDF, Office ve benzeri belgelerde script/aktif içerik.
- **Kimlik avı ve malware dağıtımı**: Kullanıcılara sunulan dosyaların kötüye kullanımı.
- **Dosya taşması/overwrite**: Var olan önemli dosyaların ezilmesi (örn. konfig, .env, .htaccess).
- **Yetki yükseltme ve veri sızıntısı**: Path traversal, log poisoning, SSRF benzeri yan etkilerle birleşen zincir saldırılar.

### 1.2 Tipik Saldırı Yüzeyi
- Profil resmi / belge / CV yükleme
- Zengin metin editörleri ve medya kütüphaneleri
- E-posta, bilet, fatura, sözleşme gibi belge iş akışları
- Self-service içerik yönetimi (CMS), eklenti/tema yükleme mekanizmaları
- API tabanlı mobil/SPA yükleme uçları (S3/GCS presigned URL vb.)

### 1.3 Zafiyet Türleri (Taksonomi)
- **T1 — Tür Doğrulama Eksikliği**: Sadece uzantıya güvenme, MIME sniffing’e bırakma, polyglot dosyalara açık olma.
- **T2 — İçerik Doğrulama Eksikliği**: Magic byte doğrulaması yok, güvenli yeniden kodlama/temizleme yok.
- **T3 — Depolama Hataları**: Web köküne yazma, herkese açık bucket, zayıf izinler, dizin listeleme.
- **T4 — İsimlendirme/Çakışma**: Rastgeleleştirme yok, predictable path, overwrite imkânı.
- **T5 — Erişim/İndirme Hataları**: Doğrudan servis, anti-virus/ICAP yok, Content-Disposition/Type yanlış.
- **T6 — İşyükü Zinciri**: Görüntü işleme, thumbnailer, OCR, dosya dönüştürücülerin zafiyetleri.
- **T7 — İş Mantığı Kusurları**: Yükleme sonrası onay akışının atlanması, rol kontrolleri zayıf.

---

## 2) Tehdit Modeli (Özet)

- **Aktörler**: Otantike veya anonim saldırgan, içerik yükleyebilen iç kullanıcı, kötü niyetli eklenti geliştiricisi.
- **Varsayımlar**: Saldırgan içerik yükleyebiliyor, dosyayı sonrasında farklı yollarla çalıştırmayı/işletmeyi deniyor.
- **Hedef**: Kod yürütme, bilgi sızdırma, sahte içerik dağıtımı, kalıcılık.
- **Kısıtlar**: İçerik güvenlik politikaları (CSP), WAF, AV, sandbox; ancak yanlış konfigürasyon sık görülür.

---

## 3) Saldırı Zinciri (Örnek Senaryo)

1) Saldırgan “.png” görünen fakat polyglot/sahte başlıklı dosya yükler.  
2) Sunucu yalnızca uzantıya güvenir, içerik doğrulamaz.  
3) Dosya web köküne veya herkese açık bucket’a yazılır.  
4) Görüntü işleyici/thumbnailer dosyayı işlerken parser bug’ı tetiklenir veya script yürür.  
5) RCE → web shell kalıcılığı → veri sızıntısı / yatay hareket.

Not: Bu zincir; **CORS yanlışları, zayıf CSP, eksik indirme başlıkları, açık dizin listeleme** gibi küçük kusurlarla birleşince çok daha pratik hâle gelir.

---

## 4) Risk Matrisi (Kısa)

- **Etkisi**: Çok yüksek (RCE, veri sızıntısı, zincir riskleri)
- **Olasılık**: Orta–yüksek (yükleme uçları yaygın, hatalı doğrulama sık)
- **Algılanabilirlik**: Düşük–orta (günlüklerde gürültü az; özel test gerekir)

---

## 5) Sık Görülen Hatalar

- Sadece dosya uzantısını kontrol etmek (jpg, png whitelisti ama içerik serbest).
- Client-side doğrulamaya güvenmek (JS ile filtre → kolayca atlanır).
- `Content-Type` başlığına güvenmek (kolay spoof).
- Magic byte/gerçek MIME doğrulaması yapmamak.
- Görseli “sadece bir resim” sayıp SVG’ye izin vermek (içinde script olabilir).
- PDF/Office belgelerini güvenli sanmak (Makro/JS/yerleşik dosyalar).
- Dosyayı web köküne kaydetmek ve doğrudan servis etmek.
- Rastgele isim üretmemek, path traversal engellememek.
- EXIF/metadata’yı temizlememek (sızıntı/istismar yüzeyi).
- Thumbnailer/convert pipeline’ını izole etmemek (ImageMagick/LibreOffice vb. zafiyetleri).

---

## 6) Güvenli Tasarım İlkeleri (Yüksek Seviye)

- **Sert Allowlist**: Uzantı + gerçek MIME + magic byte üçlü doğrulama; yalnızca **iş ihtiyacı olan** formatlara izin ver.
- **Güvenli Yeniden Kodlama**: Görselleri decode→encode; SVG, HTML, PDF gibi aktif formatları tercihen **tamamen reddet** veya güvenli dönüştür (ör. rasterize).
- **Boyut ve Nicelik Limitleri**: Maksimum boyut, çözünürlük, sayfa/katman/çerçeve limiti.
- **Depolama İzolasyonu**: Web kökü dışında, özel bucket/prefix, imzasız doğrudan erişim yok.
- **Erişim Kontrolleri**: Yetkiliye özel okuyuş, imzalı/tek kullanımlık URL, kısa TTL.
- **İsim Rastgeleleştirme**: Güçlü UUID, dizin segmentasyonu; kullanıcı adı/ID sızdırma yok.
- **Başlıklar**: İndirilecek içeriklere `Content-Disposition: attachment`; tarayıcı yürütmesini önleyici başlıklar.
- **AV/ICAP/Sandbox**: Yükleme sonrası tarama; şüpheli içerik karantina.
- **Dönüştürücüler için Sandbox**: Chroot/namespace, düşük ayrıcalık, ağsız container, kısıtlı kaynak.
- **Loglama ve İzlenebilirlik**: Yükleme isteği, kaynak IP, kullanıcı, dosya hash’i, işlem hattı olayları.
- **Güvenlik Testleri**: Pozitif/negatif test setleri, fuzzing, polyglot örnekleri, otomasyona bağlama.

---

## 7) Örnek Savunma Akışı (Psödokod)

Aşağıdaki akış, sunucu tarafı güvenli işleyişe dair **savunma-odaklı** bir şablondur (dil bağımsız):

function handleUpload(request):
  assert userIsAuthenticated(request)
  file = request.file

  # 1) Boyut ve sayısal limitler
  if file.size > MAX_SIZE or file.count > MAX_FILES:
      return reject("Dosya limitleri aşıldı")

  # 2) Ön-temizlik ve meta kısıtları
  originalName = normalizeFilename(file.name)           # unicode normalizasyonu
  if hasPathTraversal(originalName):                    # ../, %2e%2e/ vb.
      return reject("Geçersiz isim")
  if extensionNotAllowed(originalName):                 # sıkı allowlist
      return reject("İzin verilmeyen uzantı")

  # 3) İçerik doğrulama (uzantıya asla güvenme)
  headerMagic = readMagicBytes(file.stream)
  detectedMime = detectMime(headerMagic, file.stream)   # libmagic/benzeri
  if mimeNotAllowed(detectedMime):
      return reject("İzin verilmeyen MIME")

  # 4) Aktif içerikleri reddet veya güvenli dönüştür
  if isActiveFormat(detectedMime):                      # svg/html/pdf/office vb.
      if not canSafelyConvert(detectedMime):
          return reject("Aktif içerik reddedildi")
      file = safeTranscode(file)                        # ör. rasterize image/pdf

  # 5) Görsel/Medya yeniden kodlama ve metadata temizliği
  if isImage(detectedMime):
      file = decodeAndReencode(file)                    # rgb re-encode
      file = stripMetadata(file)                        # EXIF/IPTC/XMP temizle

  # 6) AV/ICAP taraması
  if scan(file) == "malicious":
      return reject("Tarama başarısız: şüpheli içerik")

  # 7) İzole depolama (web kökü dışı, private)
  randomName = randomUUID() + safeExtFor(detectedMime)
  safePath = join(PRIVATE_STORAGE_ROOT, shard(randomName))
  writeFileAtomic(safePath, file.stream, perms=0600)

  # 8) Erişim modeli: imzalı URL veya arka uç proxy indirme
  token = signDownloadToken(userId, safePath, expires=shortTTL)
  logUpload(userId, originalName, detectedMime, file.size, hash(file))
  return success({"download_token": token})

---

## 8) Yanlış Yapılandırma Örnekleri (Kısa Liste)

- Web sunucusunda `AutoIndex` açık; yüklenen içerikler dizin halinde listeleniyor.
- `X-Content-Type-Options: nosniff` eksik; tarayıcı içerik türünü “tahmin” ediyor.
- S3/GCS bucket “public-read”; herkes doğrudan görüntülüyor/indirgiyor.
- İndirilebilir içerikte `Content-Disposition: inline`; içerik tarayıcıda yürütülebiliyor.
- `CSP` gevşek; kullanıcıya sunulan görüntü/dosya alanı XSS zincirine dönüşüyor.
- Dosya dönüştürücüler root/aynı ağ içinde ve kaynak sınırı yok; parser bug’ı → RCE.

---

## 9) Test Kapsamı (Savunma-odaklı)

- **Pozitif testler**: Beklenen formatlarda, boyut limiti içinde, meta temiz, güvenli dönüştürme başarıyor.
- **Negatif testler**: Uzantı spoof, MIME spoof, magic byte uyuşmazlığı, polyglot, büyük boyut, çok sayıda parça, EXIF gizli içerik, SVG script, PDF/Office makro, path traversal, overwrite denemesi.
- **Pipeline testleri**: Thumbnailer/OCR/konvertör izolasyonu, zaman aşımı, kaynak sınırları.
- **İndirme/test başlıkları**: `Content-Type`, `Content-Disposition`, `X-Content-Type-Options`, `Cache-Control`.

---

## 10) Kullanım (Bu Repodan Nasıl Yararlanılır?)

- **/checklists/**: Uygulama ekipleri için “ön yayın”, “prod öncesi”, “periyodik denetim” kontrol listeleri.
- **/patterns/**: Güvenli tasarım örüntüleri (allowlist, transcode, AV entegrasyonu, imzalı URL).
- **/tests/**: Pozitif/negatif örnek test korpusu (aktif içerikler, polyglot’lar ve zararsız simülasyon dosyaları).
- **/hardening/**: Web sunucusu, CDN, object storage, reverse proxy ve başlık güçlendirme rehberi.
- **/playbooks/**: Olay müdahalesi, karantina, IOC toplama, log analizi, müşteri bildirim şablonları.

Not: Bu rehber **saldırı kodu** paylaşmaz; test korpusu yalnızca **zararsız** ve **savunma amaçlı** simülasyon örnekleri içerir.

---

## 11) Önemli Notlar (Etik, Hukuki ve Operasyonel)

- **Yasal Sınırlar**: Bu rehber eğitim ve savunma amaçlıdır. Yetkisiz sistemlerde test yapmak **yasadışıdır**. Sadece açık yazılı izinli, kapsamı belirlenmiş ortamlarda test yapın.
- **Canlı Sistemler**: Prod yük yollarını test ederken iş sürekliliği riskini gözetin; throttling/kota ve bakım pencereleri kullanın.
- **Veri Koruma**: Kullanıcı dosyaları kişisel veri içerebilir. Depolama-erişim süreçleri KVKK/GDPR ve şirket politikalarına uyumlu olmalıdır.
- **Güvenli Laboratuvar**: Tüm deneyler izole lab ortamında, internet erişimi kısıtlı sandbox’larda yapılmalıdır.
- **Sorumlu Açıklama**: Zafiyet bulgularını ilgili taraflara sorumlu açıklama çerçevesinde raporlayın.
- **Güncellik**: Dosya işleme kütüphaneleri (görüntü, video, belge) sık sık zafiyet alır; yamaları düzenli takip edin.
- **Saldırı Kodundan Kaçınma**: Rehber, istismarı kolaylaştıracak payload/web shell gibi zararlı içerikler sunmaz; odak savunmadır.

---

## 12) Sonuç

Unrestricted File Upload, tek bir “dosya uzantısı kontrolü” ile çözülecek bir konu değildir. **Tür + içerik + işleme hattı + depolama + dağıtım** katmanlarının **hepsinde** sıkı kontroller gerekir. Bu repodaki kontrol listeleri, güvenli örüntüler ve test yaklaşımları; ürün ekiplerinin yükleme yüzeyini “tasarımdan itibaren güvenli” hâle getirmesine yardımcı olacak şekilde kurgulanmıştır.

Devam eden bölümlerde; ayrıntılı güvenli mimari kalıpları, örnek konfigürasyonlar, pipeline izolasyonu, güvenli dönüştürme stratejileri ve denetim/CI otomasyon örnekleri yer alacaktır.
