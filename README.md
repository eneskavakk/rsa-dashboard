# 🔐 RSA Şifreleme Laboratuvarı

> **RSA algoritmasının matematiksel temellerini interaktif olarak öğreten Streamlit tabanlı eğitim uygulaması.**

---

## 📋 İçindekiler

1. [Proje Hakkında](#-proje-hakkında)
2. [Kurulum ve Çalıştırma](#-kurulum-ve-çalıştırma)
3. [Proje Yapısı](#-proje-yapısı)
4. [Modüller](#-modüller)
   - [Modül 1: Matematiksel Yardımcı Fonksiyonlar](#modül-1-matematiksel-yardımcı-fonksiyonlar)
   - [Modül 2: Streamlit Arayüzü](#modül-2-streamlit-arayüzü)
   - [Modül 3: Test Paketi](#modül-3-test-paketi)
5. [Matematiksel Arka Plan](#-matematiksel-arka-plan)
6. [Güvenlik Notları](#-güvenlik-notları)

---

## 📖 Proje Hakkında

Bu uygulama, RSA (Rivest–Shamir–Adleman) şifreleme algoritmasını sıfırdan öğrenmek isteyenler için etkileşimli bir laboratuvar sunar. Herhangi bir üçüncü taraf kriptografi kütüphanesi kullanılmadan, tüm matematiksel işlemler saf Python ile gerçekten uygulanmıştır.

### Özellikler

| Özellik | Açıklama |
|---|---|
| 🔑 Anahtar Üretimi | Otomatik (rastgele asal) veya manuel mod |
| 🔒 Şifreleme / Çözme | Karakter bazlı RSA şifreleme, adım adım tablo |
| 🛡️ Güvenlik Analizi | Brute-force simülasyonu ve zaman karmaşıklığı grafiği |
| 📚 Matematiksel Arka Plan | LaTeX formülleri, Euler teoremi, modüler aritmetik |
| 🧪 Test Paketi | 44 adet otomatik pytest testi |

---

## Kurulum ve Çalıştırma

### Gereksinimler

- Python 3.8+
- pip

### Bağımlılıkları Yükle

```bash
pip install -r requirements.txt
```

`requirements.txt` içeriği:

```
streamlit
numpy
sympy
plotly
```

### Uygulamayı Başlat

```bash
streamlit run app.py
```

Tarayıcı otomatik olarak `http://localhost:8501` adresini açar.

### Testleri Çalıştır

```bash
python -m pytest test_app.py -v
```

---

## 📁 Proje Yapısı

```
rsa-dashboard/
├── app.py              # Ana uygulama (matematik + Streamlit arayüzü)
├── test_app.py         # Pytest test paketi (44 test)
├── requirements.txt    # Python bağımlılıkları
└── .streamlit/         # Streamlit yapılandırma dosyaları
```

---

## 🔧 Modüller

### Modül 1: Matematiksel Yardımcı Fonksiyonlar

> `app.py` — Satır 1–256   
> Streamlit bağımlılığı yoktur; saf Python matematiğidir. Bağımsız olarak import edilebilir.

---

#### `gcd(a, b)` — En Büyük Ortak Bölen

**Algoritma:** Öklid Algoritması  
**Zaman Karmaşıklığı:** O(log(min(a, b)))

```python
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
```

**Matematiksel temel:**
- `gcd(a, 0) = a`
- `gcd(a, b) = gcd(b, a mod b)`

**RSA'daki rolü:** `gcd(e, φ(n)) = 1` şartını doğrulamak için kullanılır. Bu şart, açık ve özel anahtarın çifti olmasını garanti eder.

---

#### `extended_gcd(a, b)` — Genişletilmiş Öklid Algoritması

**Döndürür:** `(gcd, x, y)` üçlüsü

```python
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y
```

**Çözdüğü denklem:** `ax + by = gcd(a, b)`

**RSA'daki rolü:** `mod_inverse` fonksiyonuna temel oluşturur. `e·d ≡ 1 (mod φ(n))` denkleminin çözümünü bulmak için kullanılır.

---

#### `mod_inverse(e, phi)` — Modüler Ters

**Döndürür:** `d` değeri (ters varsa) veya `None` (ters yoksa)

```python
def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        return None  # Modüler ters mevcut değil
    return x % phi
```

**Matematiksel temel:** `e · d ≡ 1 (mod φ(n))`

**RSA'daki rolü:** Özel anahtarı (`d`) hesaplar. `gcd(e, φ(n)) ≠ 1` ise ters yoktur, anahtar üretilemez.

---

#### `is_prime_miller_rabin(n, k=20)` — Miller-Rabin Asallık Testi

**Algoritma:** Miller-Rabin olasılıksal asallık testi  
**Zaman Karmaşıklığı:** O(k · log²(n))  
**Hata Olasılığı:** En fazla `4⁻ᵏ` (k=20 için ihmal edilebilir)

**Algoritmanın adımları:**

1. `n - 1 = 2^r · d` olacak şekilde `r` ve `d` bulunur.
2. Rastgele `a` seçilir (`2 ≤ a ≤ n-2`).
3. `x = a^d mod n` hesaplanır.
4. Aşağıdaki koşullardan biri sağlanmalıdır:
   - `x ≡ 1 (mod n)`
   - `x ≡ -1 (mod n)` herhangi bir `2^i · d` için

```python
def is_prime_miller_rabin(n, k=20):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
```

**RSA'daki rolü:** Seçilen `p` ve `q`'nun gerçekten asal olduğunu doğrular. Geleneksel O(√n) testine kıyasla büyük sayılar için çok daha hızlıdır.

---

#### `generate_prime(bits)` — Rastgele Asal Sayı Üretimi

**Yöntem:** Rastgele örnekle ve Miller-Rabin ile test et

```python
def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1))  # En yüksek bit = 1 (bit uzunluğunu garantile)
        n |= 1                   # Son bit = 1 (tek sayı)
        if is_prime_miller_rabin(n):
            return n
```

**RSA'daki rolü:** Anahtar üretiminin temel adımı. Üretilen `p` ve `q` asalları `n = p × q` modülünü oluşturur.

---

#### `brute_force_factor(n)` — Brute-Force Çarpanlara Ayırma

**Algoritma:** Trial Division  
**Zaman Karmaşıklığı:** O(√n)  
**Döndürür:** `(p, q, süre)` üçlüsü

```python
def brute_force_factor(n):
    start_time = time.time()
    if n % 2 == 0:
        return 2, n // 2, time.time() - start_time
    i = 3
    while i * i <= n:
        if n % i == 0:
            return i, n // i, time.time() - start_time
        i += 2
    return n, 1, time.time() - start_time  # n zaten asal
```

**RSA'daki rolü:** Güvenlik laboratuvarında küçük anahtarların ne kadar hızlı kırılabileceğini göstermek için kullanılır. 2048-bit gerçek RSA anahtarları için bu yöntem evrenin ömründen uzun sürer.

---

#### `generate_rsa_keys(p, q)` — RSA Anahtar Çifti Üretimi

**Döndürür:** `(n, phi_n, e, d)` dörtlüsü

```python
def generate_rsa_keys(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    if e >= phi_n:
        e = 3
        while e < phi_n:
            if gcd(e, phi_n) == 1:
                break
            e += 2
    if gcd(e, phi_n) != 1:
        return None, None, None, None
    d = mod_inverse(e, phi_n)
    return n, phi_n, e, d
```

**Adım adım:**

| Adım | İşlem | Açıklama |
|---|---|---|
| 1 | `n = p × q` | Modül hesaplama |
| 2 | `φ(n) = (p-1)(q-1)` | Euler'in Totient fonksiyonu |
| 3 | `e` seçimi | `gcd(e, φ(n)) = 1` şartını sağlayan üs (tercih: 65537) |
| 4 | `d = e⁻¹ mod φ(n)` | Özel anahtar hesaplama |

---

#### `encrypt_char(m, e, n)` ve `decrypt_char(c, d, n)` — Tek Karakteri Şifrele/Çöz

```python
def encrypt_char(m, e, n):
    return pow(m, e, n)   # c = m^e mod n

def decrypt_char(c, d, n):
    return pow(c, d, n)   # m = c^d mod n
```

Python'un yerleşik `pow(base, exp, mod)` fonksiyonu "square-and-multiply" algoritması ile O(log(exp)) karmaşıklığında çalışır.

---

#### `encrypt_message(message, e, n)` ve `decrypt_message(encrypted_list, d, n)` — Metin Şifreleme/Çözme

Her karakter bağımsız olarak şifrelenir (textbook RSA — **uyarı:** sadece eğitim amaçlıdır).

```python
def encrypt_message(message, e, n):
    return [encrypt_char(ord(char), e, n) for char in message]

def decrypt_message(encrypted_list, d, n):
    return "".join(chr(decrypt_char(c, d, n)) for c in encrypted_list)
```

**Kısıtlama:** Her karakterin ASCII değeri `n`'den küçük olmalıdır (`ord(char) < n`). Küçük asal sayılar kullanıldığında bu koşul sağlanamayabilir.

---

### Modül 2: Streamlit Arayüzü

> `app.py` — Satır 257–1204  
> `main()` fonksiyonu içinde tanımlıdır.

---

#### Sidebar: Anahtar Ayarları

Uygulamanın sol paneli, iki farklı anahtar üretim modunu sunar:

| Mod | Açıklama |
|---|---|
| 🤖 **Otomatik** | Slider ile 8–64 bit arası seçim; `generate_prime()` çağrılır |
| ✏️ **Manuel** | Kullanıcı kendi `p` ve `q` değerlerini girer; anlık asallık doğrulaması yapılır |

Her iki modda da hesaplanan `n`, `φ(n)`, `e` ve `d` değerleri `st.session_state`'e kaydedilir ve tüm sekmeler tarafından paylaşılır.

---

#### Sekme 1: 🔒 Şifreleme & Çözme

İki sütunlu düzende şifreleme ve çözme işlemleri yapılır:

**Sol Sütun — Şifreleme:**
- Kullanıcı metin girer
- ASCII sınır kontrolü yapılır (`ord(char) < n`)
- Her karakter için adım adım tablo gösterilir: `Karakter → ASCII → m^e mod n → c`

**Sağ Sütun — Çözme:**
- Şifreli değer listesi (Python liste formatı) girilir
- `eval()` ile parse edilir
- Her `c` değeri için adım adım çözme tablosu gösterilir

---

#### Sekme 2: 🛡️ Güvenlik Analizi (Güvenlik Laboratuvarı)

**Sol Panel — Tek Anahtar Saldırısı:**
- Mevcut `n` değerine brute-force uygulanır
- `brute_force_factor(n)` çağrılır, süre ölçülür
- Bulunan `p` ve `q` ile doğrulama gösterilir

**Sağ Panel — Zaman Karmaşıklığı Analizi:**
- Kullanıcı 8–40 bit arası birden fazla bit uzunluğu seçer
- Her uzunluk için birden fazla deneme yapılır (ortalama alınır)
- Plotly ile logaritmik eksenli çizgi grafik çizilir
- Sonuç tablosu: `bit uzunluğu → ortalama/min/max kırma süresi`

---

#### Sekme 3: 📚 Matematiksel Arka Plan

Öğretici içerik sekmeleri sırasıyla:

1. **RSA Algoritmasına Genel Bakış** — Tarihçe ve temel kavramlar
2. **Anahtar Üretim Süreci** — 5 adımda LaTeX formülleri
3. **Şifreleme ve Çözme** — `c = m^e mod n` ve `m = c^d mod n` formülleri
4. **Euler Teoremi** — Neden çalıştığının matematiksel kanıtı
5. **Modüler Aritmetik** — Toplama, çarpma ve üs alma kuralları
6. **Hesaplama Zorluğu** — Brute-force T(n) = O(√n) karmaşıklık tablosu
7. **İnteraktif Örnek** — Mevcut anahtarla tek karakteri adım adım şifrele/çöz

---

### Modül 3: Test Paketi

> `test_app.py` — 44 adet pytest testi

#### Test Sınıfları

| Sınıf | Test Sayısı | Kapsamı |
|---|---|---|
| `TestGCD` | 6 | Öklid algoritması, değişme özelliği, sınır durumları |
| `TestExtendedGCD` | 3 | `ax + by = gcd(a,b)` eşitliği doğrulaması |
| `TestModInverse` | 4 | `e·d ≡ 1 (mod φ)`, ters yok durumu, simetri |
| `TestMillerRabin` | 5 | Bilinen asallar, bileşik sayılar, sınır durumları |
| `TestGeneratePrime` | 3 | Bit uzunluğu, asallık, tek sayı garantisi |
| `TestBruteForce` | 5 | Çift sayı, asal sayı, çarpım doğrulaması |
| `TestGenerateRSAKeys` | 5 | n, φ, e, d ilişkileri ve büyük asallar |
| `TestEncryptDecrypt` | 9 | Tek karakter, tam metin, boş mesaj, aralık kontrolü |
| `TestEndToEnd` | 4 | Küçük/büyük asallarla tam RSA akışı, yanlış anahtar testi |

#### Testleri Çalıştırma

```bash
# Tüm testler
python -m pytest test_app.py -v

# Sadece belirli bir sınıf
python -m pytest test_app.py::TestGCD -v

# Özet rapor
python -m pytest test_app.py --tb=short
```

**Son çalışma sonucu:**
```
44 passed in 0.11s
```

---

## 📐 Matematiksel Arka Plan

### RSA'nın Çalışma Prensibi

```
ANAHTAR ÜRETİMİ:
  1. p, q seç (iki büyük asal sayı)
  2. n = p × q
  3. φ(n) = (p-1)(q-1)
  4. e seç: gcd(e, φ(n)) = 1  →  Açık Anahtar: (e, n)
  5. d = e⁻¹ mod φ(n)         →  Özel Anahtar: (d, n)

ŞİFRELEME:  c = m^e mod n
ÇÖZME:      m = c^d mod n
```

### Neden Güvenlidir?

`n`'den `p` ve `q`'yu bulmak — **Tamsayı Çarpanlarına Ayırma Problemi** — bilinen hiçbir polinom zamanlı algoritmanın çözemediği bir problemdir. Kırma süresi anahtar uzunluğuyla **üstel** olarak artar:

| n Bit Uzunluğu | Brute-Force Süre (1 GHz CPU) |
|---|---|
| 32 bit | ~65 mikrosaniye |
| 64 bit | ~4.3 saniye |
| 128 bit | ~570 yıl |
| 256 bit | ~10³¹ yıl |
| 2048 bit | ~10³⁰¹ yıl |

---

## ⚠️ Güvenlik Notları

> **Bu uygulama yalnızca eğitim amaçlıdır.**

Gerçek dünya uygulamalarında şu farklılıklar bulunur:

| Bu Uygulama | Gerçek RSA |
|---|---|
| Her karakter ayrı şifrelenir | PKCS#1 / OAEP dolgu şeması kullanılır |
| 8–64 bit asallar | Minimum 2048 bit anahtar |
| Rastgele asal üretimi | Güvenli rastgele kaynak (CSPRNG) kullanılır |
| `eval()` ile parse | Güvenli veri işleme |

Gerçek şifreleme için Python'da [`cryptography`](https://cryptography.io) kütüphanesini kullanın:

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
```
