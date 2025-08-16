# 🛡️ WAF / Filtre Bypass Teknikleri

Web Application Firewall (WAF), web uygulamalarını zararlı girişlere karşı korumak için tasarlanmış bir güvenlik katmanıdır. Ancak, yanlış yapılandırılmış veya zayıf kurallar içeren WAF’lar bypass edilebilir. Bu ders notunda güncel bypass teknikleri, PoC örnekleri, kullanım senaryoları, savunma yöntemleri ve mülakat soruları detaylı olarak ele alınmıştır.

---

## 📌 1. HTTP Parameter Pollution (HPP)

**Açıklama:**  
WAF, aynı parametreyi birden fazla kez gönderdiğinizde sadece ilkini kontrol ediyor olabilir.  
Bu, saldırganın filtreleri atlamasını sağlar.

**PoC Örneği:**  
GET isteği:  
`http://target.com/search.php?query=<script>alert(1)</script>&query=test`

**Kullanım:**  
- İlk parametre filtrelenebilir, ikinci parametre işlenebilir.  
- XSS veya SQL Injection payload’ları için kullanılabilir.

**Savunma:**  
- Tüm parametreleri normalize et.  
- Sunucuda tek bir değer üzerinden işlem yap.

---

## 📌 2. URL Encoding / Double Encoding

**Açıklama:**  
WAF bazı özel karakterleri engellese de, karakterlerin URL veya Unicode encoding’i bypass için kullanılabilir.

**PoC Örneği:**  
- Normal payload: `<script>alert(1)</script>`  
- URL encoded: `%3Cscript%3Ealert(1)%3C/script%3E`  
- Double encoded: `%253Cscript%253Ealert(1)%253C/script%253E`

**Kullanım:**  
- WAF sadece ilk decode işleminden sonra filtre uyguluyorsa bypass gerçekleşir.  

**Savunma:**  
- Tüm gelen inputları normalize et ve decode etmeden önce filtrele.  

---

## 📌 3. Case Variation

**Açıklama:**  
Bazı WAF’lar büyük/küçük harf duyarlılığına göre filtre uygular. Payload içinde case değişikliği bypass sağlar.

**PoC Örneği:**  
- Normal: `<script>alert(1)</script>`  
- Bypass: `<ScRiPt>alert(1)</sCrIpT>`

**Kullanım:**  
- XSS veya komut injection payload’larında sık kullanılır.  

**Savunma:**  
- Input’ları lowercase veya normalize edilmiş şekilde filtrele.  

---

## 📌 4. Comment / Whitespace Injection

**Açıklama:**  
SQL, XSS veya komut payload’larında WAF’lar whitespace veya yorumları filtrelemeyebilir.

**PoC Örneği:**  
- SQL Injection: `SELECT/*comment*/password FROM users`  
- XSS: `<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>`

**Kullanım:**  
- WAF yorum ve whitespace karakterlerini dikkate almadığında bypass sağlanır.  

**Savunma:**  
- Payload normalization ve regex tabanlı tam filtreleme.  

---

## 📌 5. Alternate Encoding / Obfuscation

**Açıklama:**  
UTF-7, UTF-16, HTML entity encoding gibi tekniklerle WAF atlatılabilir.

**PoC Örneği:**  
- XSS: `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`  

**Kullanım:**  
- WAF UTF-8 check yapıyor ama HTML entity decode etmiyorsa bypass olur.  

**Savunma:**  
- Tüm karakterleri normalize et, entity decode sonrası filtre uygula.  

---

## 📌 6. HTTP Method / Header Manipulation

**Açıklama:**  
WAF bazı HTTP metodlarını veya header kombinasyonlarını filtrelemez.

**PoC Örneği:**  
- PUT veya PATCH metodunu kullanarak dosya yükleme bypass.  
- X-HTTP-Method-Override header ile POST → PUT değişimi.  

**Kullanım:**  
- Dosya upload veya API endpoint bypass’ları için sık tercih edilir.  

**Savunma:**  
- Tüm HTTP metodlarını doğrula.  
- Yalnızca izin verilen metodları kabul et.  

---

## 📌 7. Rate Limit / IP Rotation Bypass

**Açıklama:**  
WAF, saldırıyı engellemek için rate limit uygular. Saldırgan IP değiştirerek veya proxy kullanarak bypass edebilir.

**PoC Örneği:**  
- TOR veya VPN ile farklı IP’lerden ardışık payload gönderimi.  

**Kullanım:**  
- Brute force, credential stuffing veya multiple payload denemelerinde kullanılır.  

**Savunma:**  
- Captcha, MFA, ve anomaly detection ile kullanıcı davranışını izle.  

---

## 🛡️ Savunma ve Best Practices

1. **Payload normalization**: tüm inputları decode ve normalize et.  
2. **Case insensitive filtreleme**: büyük/küçük harf farklılıklarını kontrol et.  
3. **Comment ve whitespace kontrolü**: payload obfuscation tespit et.  
4. **Method ve header doğrulama**: sadece izin verilenleri kabul et.  
5. **Rate limit & anomaly detection**: IP veya kullanıcı davranışlarını izle.  
6. **Multi-layer defense**: WAF + IDS/IPS + input validation + logging.  
7. **Düzenli test**: WAF bypass testlerini CI/CD veya penetration test süreçlerine dahil et.  

---

## 💡 Mülakat Soruları

1. WAF bypass nedir ve hangi durumlarda kullanılır?  
2. URL encoding ve double encoding farkı nedir, örnek verin.  
3. SQL Injection veya XSS payload’larını WAF’tan geçirebilmek için hangi teknikler kullanılır?  
4. HTTP method ve header manipülasyonu nasıl bypass sağlar?  
5. WAF bypass testleri için hangi araçlar ve metodlar önerirsiniz?  
6. Case variation ve whitespace/comment injection nasıl tespit edilir?  
7. Multi-layer defense yaklaşımı neden önemlidir?  

---

## ✅ Sonuç

WAF, web uygulamalarını korumada önemli bir katman olsa da, zayıf konfigürasyon ve eksik filtreleme saldırganlar tarafından bypass edilebilir.  
Güncel bypass tekniklerini anlamak, hem pentester hem de güvenlik uzmanı için kritik öneme sahiptir.  
En iyi savunma, **çok katmanlı güvenlik, input normalization ve sürekli test** ile sağlanır.  
