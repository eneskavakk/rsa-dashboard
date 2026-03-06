"""
RSA Eğitim Dashboardu (RSA Education Dashboard)
=================================================
Bu uygulama, RSA şifreleme algoritmasının matematiksel temellerini
interaktif bir şekilde öğretmek için tasarlanmıştır.

Modüller:
  1. Anahtar Üretimi (Key Generation)
  2. Şifreleme / Çözme (Encoder / Decoder)
  3. Güvenlik Laboratuvarı (Security Lab) - Brute-Force saldırı simülasyonu
  4. Matematiksel Arka Plan (Mathematical Background)

Gereksinimler: streamlit, numpy, sympy, plotly
Çalıştırma: streamlit run app.py
"""

import streamlit as st
import numpy as np
import sympy
import plotly.graph_objects as go
import time
import random
import math

# =============================================================================
# BÖLÜM 1: MATEMATİKSEL YARDIMCI FONKSİYONLAR
# =============================================================================

def gcd(a, b):
    """
    Öklid Algoritması (Euclidean Algorithm)
    İki sayının en büyük ortak bölenini (EBOB) hesaplar.
    
    Matematiksel formül:
        gcd(a, 0) = a
        gcd(a, b) = gcd(b, a mod b)
    """
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Genişletilmiş Öklid Algoritması (Extended Euclidean Algorithm)
    ax + by = gcd(a, b) denkleminin x ve y çözümlerini bulur.
    
    Döndürür: (gcd, x, y) üçlüsü
    Bu fonksiyon modüler ters hesaplamada kullanılır.
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(e, phi):
    """
    Modüler Ters Hesaplama (Modular Multiplicative Inverse)
    e * d ≡ 1 (mod φ(n)) denklemini sağlayan d değerini bulur.
    
    Genişletilmiş Öklid Algoritması kullanılarak hesaplanır.
    Eğer ters yoksa (gcd(e, φ) ≠ 1), None döndürür.
    """
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        return None  # Modüler ters mevcut değil
    return x % phi


def is_prime_miller_rabin(n, k=20):
    """
    Miller-Rabin Asallık Testi (Miller-Rabin Primality Test)
    Bir sayının asal olup olmadığını olasılıksal olarak test eder.
    
    Parametreler:
        n: Test edilecek sayı
        k: Test tekrar sayısı (yükseldikçe doğruluk artar)
    
    Matematiksel temel:
        n - 1 = 2^r * d şeklinde yazılır.
        Rastgele seçilen a için:
            a^d ≡ 1 (mod n) veya
            a^(2^i * d) ≡ -1 (mod n)  (0 ≤ i < r)
        koşullarından biri sağlanmalıdır.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # n - 1 = 2^r * d olacak şekilde r ve d'yi bul
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # k kez test yap
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # a^d mod n

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)  # x^2 mod n
            if x == n - 1:
                break
        else:
            return False  # Bileşik (composite) sayı

    return True  # Büyük olasılıkla asal


def generate_prime(bits):
    """
    Belirtilen bit uzunluğunda rastgele bir asal sayı üretir.
    
    Yöntem:
        1. Belirtilen bit aralığında rastgele tek sayı üret
        2. Miller-Rabin testi ile asallığını kontrol et
        3. Asal bulunana kadar tekrarla
    """
    while True:
        # Belirtilen bit uzunluğunda rastgele bir sayı üret
        n = random.getrandbits(bits)
        # En yüksek biti 1 yap (bit uzunluğunu garanti altına al)
        n |= (1 << (bits - 1))
        # Son biti 1 yap (tek sayı olmasını sağla)
        n |= 1
        if is_prime_miller_rabin(n):
            return n


def brute_force_factor(n):
    """
    Brute-Force Çarpanlara Ayırma (Brute-Force Factorization)
    Verilen n sayısını en küçük asal çarpanını bularak çarpanlarına ayırır.
    
    Bu fonksiyon, RSA'nın güvenlik temelini anlamak için kullanılır.
    Küçük n değerleri için hızlı çalışır, büyük n değerleri için
    katlanarak artan süre gerektirir.
    
    Zaman Karmaşıklığı: O(√n)
    
    Döndürür: (p, q, süre) üçlüsü
    """
    start_time = time.time()

    if n % 2 == 0:
        elapsed = time.time() - start_time
        return 2, n // 2, elapsed

    # 3'ten √n'ye kadar tek sayıları dene
    i = 3
    while i * i <= n:
        if n % i == 0:
            elapsed = time.time() - start_time
            return i, n // i, elapsed
        i += 2

    elapsed = time.time() - start_time
    return n, 1, elapsed  # n zaten asal


def generate_rsa_keys(p, q):
    """
    RSA Anahtar Çifti Üretimi
    
    Adımlar:
        1. n = p × q  (Modül)
        2. φ(n) = (p-1)(q-1)  (Euler'in Totient Fonksiyonu)
        3. e seç: 1 < e < φ(n) ve gcd(e, φ(n)) = 1
        4. d hesapla: e × d ≡ 1 (mod φ(n))
    
    Döndürür: (n, phi_n, e, d) dörtlüsü
    """
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # e değerini seç (genellikle 65537 tercih edilir)
    e = 65537
    if e >= phi_n:
        # φ(n) küçükse, uygun bir e bul
        e = 3
        while e < phi_n:
            if gcd(e, phi_n) == 1:
                break
            e += 2

    if gcd(e, phi_n) != 1:
        return None, None, None, None

    # Özel anahtar d'yi hesapla
    d = mod_inverse(e, phi_n)
    if d is None:
        return None, None, None, None

    return n, phi_n, e, d


def encrypt_char(m, e, n):
    """
    Tek bir karakteri (integer değerini) RSA ile şifreler.
    
    Formül: c = m^e mod n
    Python'un pow(base, exp, mod) fonksiyonu kullanılır (verimli modüler üs alma).
    """
    return pow(m, e, n)


def decrypt_char(c, d, n):
    """
    Şifrelenmiş bir değeri RSA ile çözer.
    
    Formül: m = c^d mod n
    """
    return pow(c, d, n)


def encrypt_message(message, e, n):
    """
    Bir metin mesajını RSA ile şifreler.
    
    Her karakter ASCII değerine dönüştürülür ve ayrı ayrı şifrelenir.
    c_i = m_i^e mod n
    
    Döndürür: Şifrelenmiş değerlerin listesi
    """
    encrypted = []
    for char in message:
        m = ord(char)  # Karakteri ASCII değerine çevir
        c = encrypt_char(m, e, n)
        encrypted.append(c)
    return encrypted


def decrypt_message(encrypted_list, d, n):
    """
    RSA ile şifrelenmiş bir mesajı çözer.
    
    Her şifreli değer çözülüp ASCII karakterine dönüştürülür.
    m_i = c_i^d mod n
    
    Döndürür: Çözülmüş metin
    """
    decrypted = ""
    for c in encrypted_list:
        m = decrypt_char(c, d, n)
        decrypted += chr(m)
    return decrypted


# =============================================================================
# BÖLÜM 2: STREAMLIT ARAYÜZÜ
# =============================================================================

def main():
    """Ana uygulama fonksiyonu - Streamlit arayüzünü oluşturur."""

    # Sayfa yapılandırması
    st.set_page_config(
        page_title="RSA Şifreleme Laboratuvarı",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Özel CSS stilleri
    st.markdown("""
    <style>
        /* Ana tema renkleri */
        :root {
            --primary: #6C63FF;
            --secondary: #FF6584;
            --accent: #00D9A6;
            --bg-dark: #0E1117;
            --card-bg: #1A1D23;
            --text-primary: #E2E8F0;
            --text-secondary: #CBD5E0;
        }
        
        /* Başlık stili */
        .main-title {
            background: linear-gradient(135deg, #6C63FF 0%, #FF6584 50%, #00D9A6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5rem;
            font-weight: 800;
            text-align: center;
            margin-bottom: 0.5rem;
            font-family: 'Inter', sans-serif;
        }
        
        .subtitle {
            text-align: center;
            color: #9CA3AF !important;
            font-size: 1.1rem;
            margin-bottom: 2rem;
        }
        
        /* Bilgi kartları */
        .info-card {
            background: linear-gradient(135deg, #1A1D23 0%, #262A33 100%);
            border: 1px solid #2D3748;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 0.75rem 0;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            color: #E2E8F0 !important;
        }
        .info-card strong {
            color: #F1F5F9 !important;
        }
        .info-card code {
            color: #A5B4FC !important;
            background: rgba(99, 102, 241, 0.15) !important;
            padding: 2px 6px;
            border-radius: 4px;
        }
        .info-card em {
            color: #CBD5E0 !important;
        }
        
        .key-card {
            background: linear-gradient(135deg, #1E2530 0%, #1A2332 100%);
            border: 1px solid #2D4A7A;
            border-radius: 12px;
            padding: 1.2rem;
            margin: 0.5rem 0;
            color: #E2E8F0 !important;
        }
        .key-card strong {
            color: #F1F5F9 !important;
        }
        .key-card code {
            color: #93C5FD !important;
            background: rgba(59, 130, 246, 0.15) !important;
            padding: 2px 6px;
            border-radius: 4px;
        }
        
        /* Badge stilleri */
        .badge-public {
            background: linear-gradient(135deg, #059669, #10B981);
            padding: 4px 12px;
            border-radius: 20px;
            color: white !important;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }
        
        .badge-private {
            background: linear-gradient(135deg, #DC2626, #EF4444);
            padding: 4px 12px;
            border-radius: 20px;
            color: white !important;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }
        
        /* Matematiksel formül kutusu */
        .math-box {
            background: #1A1D23;
            border-left: 4px solid #6C63FF;
            padding: 1rem 1.5rem;
            margin: 1rem 0;
            border-radius: 0 8px 8px 0;
            color: #E2E8F0 !important;
        }
        .math-box strong {
            color: #F1F5F9 !important;
        }
        
        /* Güvenlik seviye göstergesi */
        .security-low { color: #EF4444 !important; font-weight: bold; }
        .security-medium { color: #F59E0B !important; font-weight: bold; }
        .security-high { color: #10B981 !important; font-weight: bold; }
        
        /* Sidebar stili */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0E1117 0%, #1A1D23 100%);
        }
        
        /* Metrik kartları */
        [data-testid="stMetric"] {
            background: linear-gradient(135deg, #1A1D23, #262A33);
            border: 1px solid #2D3748;
            border-radius: 10px;
            padding: 12px;
        }
        
        /* Sekme stilleri */
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
        }
        .stTabs [data-baseweb="tab"] {
            border-radius: 8px;
            padding: 10px 24px;
        }
        
        /* Tablo stili */
        .crypto-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            border-radius: 10px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .crypto-table th {
            background: #2D3748;
            color: #E2E8F0 !important;
            padding: 10px 16px;
            font-weight: 600;
        }
        .crypto-table td {
            background: #1A1D23;
            color: #CBD5E0 !important;
            padding: 8px 16px;
            border-top: 1px solid #2D3748;
        }
        .crypto-table td code {
            color: #A5B4FC !important;
            background: rgba(99, 102, 241, 0.15) !important;
            padding: 2px 6px;
            border-radius: 4px;
        }
        .crypto-table td strong {
            color: #F1F5F9 !important;
        }
        
        /* Footer stili */
        .footer-text {
            text-align: center;
            color: #6B7280 !important;
            padding: 1rem;
        }
        .footer-text p {
            color: #6B7280 !important;
        }
        .footer-text code {
            color: #A5B4FC !important;
        }
    </style>
    """, unsafe_allow_html=True)

    # Başlık
    st.markdown('<p class="main-title">🔐 RSA Şifreleme Laboratuvarı</p>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">İnteraktif RSA Algoritması Eğitim ve Güvenlik Analiz Aracı</p>', unsafe_allow_html=True)

    # =========================================================================
    # SIDEBAR: ANAHTAR AYARLARI
    # =========================================================================
    with st.sidebar:
        st.markdown("## 🔑 Anahtar Ayarları")
        st.markdown("---")

        # Anahtar üretim modu seçimi
        mode = st.radio(
            "Anahtar Üretim Modu",
            ["🤖 Otomatik", "✏️ Manuel"],
            help="Otomatik mod: Sistem rastgele asal üretir.\nManuel mod: Kendi asal sayılarınızı girin."
        )

        if mode == "🤖 Otomatik":
            # Otomatik mod: Bit uzunluğu seçimi
            bit_length = st.slider(
                "Asal Sayı Bit Uzunluğu",
                min_value=8,
                max_value=64,
                value=16,
                step=4,
                help="Daha yüksek bit uzunluğu = Daha güvenli ama daha yavaş"
            )

            if st.button("🔄 Yeni Anahtar Üret", use_container_width=True, type="primary"):
                with st.spinner("Asal sayılar üretiliyor..."):
                    p = generate_prime(bit_length)
                    q = generate_prime(bit_length)
                    # p ve q'nun farklı olmasını sağla
                    while q == p:
                        q = generate_prime(bit_length)
                    st.session_state['p'] = p
                    st.session_state['q'] = q

            # İlk çalışmada varsayılan değerler
            if 'p' not in st.session_state:
                st.session_state['p'] = generate_prime(bit_length)
                st.session_state['q'] = generate_prime(bit_length)
                while st.session_state['q'] == st.session_state['p']:
                    st.session_state['q'] = generate_prime(bit_length)

            p = st.session_state['p']
            q = st.session_state['q']

        else:
            # Manuel mod: Kullanıcıdan p ve q girişi
            st.markdown("#### Asal Sayı Girişi")
            p = st.number_input("p (asal sayı)", min_value=2, value=61, step=1,
                                help="Bir asal sayı girin (örn: 61)")
            q = st.number_input("q (asal sayı)", min_value=2, value=53, step=1,
                                help="p'den farklı bir asal sayı girin (örn: 53)")

            # Asallık kontrolü
            if not is_prime_miller_rabin(p):
                st.error(f"⚠️ {p} asal değil!")
            if not is_prime_miller_rabin(q):
                st.error(f"⚠️ {q} asal değil!")
            if p == q:
                st.warning("⚠️ p ve q farklı olmalıdır!")

        st.markdown("---")

        # Anahtarları hesapla ve göster
        if is_prime_miller_rabin(p) and is_prime_miller_rabin(q) and p != q:
            n, phi_n, e, d = generate_rsa_keys(p, q)

            if n is not None:
                # Session state'e kaydet
                st.session_state['n'] = n
                st.session_state['phi_n'] = phi_n
                st.session_state['e'] = e
                st.session_state['d'] = d
                st.session_state['current_p'] = p
                st.session_state['current_q'] = q

                st.markdown("### 📊 Hesaplanan Değerler")

                # Asal sayılar
                st.markdown(f"""
                <div class="key-card">
                    <strong>🔢 Asal Sayılar</strong><br>
                    <code>p = {p}</code><br>
                    <code>q = {q}</code>
                </div>
                """, unsafe_allow_html=True)

                # Modül ve Euler's Totient
                st.markdown(f"""
                <div class="key-card">
                    <strong>📐 Modül & Totient</strong><br>
                    <code>n = p × q = {n}</code><br>
                    <code>φ(n) = (p-1)(q-1) = {phi_n}</code>
                </div>
                """, unsafe_allow_html=True)

                # Açık anahtar
                st.markdown(f"""
                <div class="key-card">
                    <span class="badge-public">Açık Anahtar (Public)</span><br><br>
                    <code>e = {e}</code><br>
                    <code>n = {n}</code>
                </div>
                """, unsafe_allow_html=True)

                # Özel anahtar
                st.markdown(f"""
                <div class="key-card">
                    <span class="badge-private">Özel Anahtar (Private)</span><br><br>
                    <code>d = {d}</code><br>
                    <code>n = {n}</code>
                </div>
                """, unsafe_allow_html=True)

                # Güvenlik seviyesi
                n_bits = n.bit_length()
                if n_bits < 32:
                    sec_class = "security-low"
                    sec_text = "Düşük (Eğitim Amaçlı)"
                elif n_bits < 64:
                    sec_class = "security-medium"
                    sec_text = "Orta"
                else:
                    sec_class = "security-high"
                    sec_text = "Yüksek"

                st.markdown(f"""
                <div class="key-card">
                    <strong>🛡️ Güvenlik Seviyesi</strong><br>
                    Anahtar Uzunluğu: <code>{n_bits} bit</code><br>
                    Seviye: <span class="{sec_class}">{sec_text}</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.error("Anahtar üretilemedi. Lütfen farklı asal sayılar deneyin.")
        else:
            st.warning("Geçerli asal sayılar girilmeli ve p ≠ q olmalı.")

    # =========================================================================
    # ANA EKRAN: SEKMELİ YAPI
    # =========================================================================

    # Anahtarların hazır olup olmadığını kontrol et
    keys_ready = all(k in st.session_state for k in ['n', 'e', 'd', 'phi_n'])

    # Sekmeler
    tab1, tab2, tab3 = st.tabs([
        "🔒 Şifreleme & Çözme",
        "🛡️ Güvenlik Analizi",
        "📚 Matematiksel Arka Plan"
    ])

    # =====================================================================
    # SEKME 1: ŞİFRELEME & ÇÖZME
    # =====================================================================
    with tab1:
        if not keys_ready:
            st.info("⬅️ Lütfen önce sidebar'dan anahtar ayarlarını yapın.")
        else:
            n = st.session_state['n']
            e = st.session_state['e']
            d = st.session_state['d']

            st.markdown("### ✉️ Mesaj Şifreleme")

            # LaTeX açıklama
            st.markdown("""
            <div class="math-box">
                <strong>Şifreleme Formülü:</strong>
            </div>
            """, unsafe_allow_html=True)
            st.latex(r"c = m^e \mod n")

            st.markdown("""
            <div class="math-box">
                <strong>Çözme Formülü:</strong>
            </div>
            """, unsafe_allow_html=True)
            st.latex(r"m = c^d \mod n")

            st.markdown("---")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### 🔐 Şifreleme (Encryption)")
                plaintext = st.text_area(
                    "Şifrelenecek Metin",
                    value="Merhaba RSA!",
                    height=100,
                    key="encrypt_input",
                    help="ASCII karakterler kullanın. Her karakter ayrı şifrelenir."
                )

                # ASCII değer kontrolü
                max_ascii = max((ord(c) for c in plaintext), default=0) if plaintext else 0
                if max_ascii >= n:
                    st.error(f"⚠️ Karakter ASCII değeri ({max_ascii}) modül n ({n}) değerinden küçük olmalıdır. Daha büyük asal sayılar seçin.")

                if st.button("🔒 Şifrele", use_container_width=True, type="primary"):
                    if plaintext and max_ascii < n:
                        encrypted = encrypt_message(plaintext, e, n)
                        st.session_state['encrypted'] = encrypted
                        st.session_state['original_text'] = plaintext

                        st.success("✅ Mesaj başarıyla şifrelendi!")

                        # Şifreleme detay tablosu
                        st.markdown("##### 📋 Adım Adım Şifreleme")
                        table_html = """
                        <table class="crypto-table">
                            <tr>
                                <th>Karakter</th>
                                <th>ASCII (m)</th>
                                <th>m^e mod n</th>
                                <th>Şifreli (c)</th>
                            </tr>
                        """
                        for i, char in enumerate(plaintext):
                            m = ord(char)
                            c = encrypted[i]
                            table_html += f"""
                            <tr>
                                <td><strong>{char}</strong></td>
                                <td>{m}</td>
                                <td>{m}^{e} mod {n}</td>
                                <td><code>{c}</code></td>
                            </tr>
                            """
                        table_html += "</table>"
                        st.markdown(table_html, unsafe_allow_html=True)

                        # Şifreli çıktı
                        st.markdown("##### 🔢 Şifrelenmiş Veri")
                        st.code(str(encrypted), language="python")

            with col2:
                st.markdown("#### 🔓 Çözme (Decryption)")

                # Şifreli veri girişi
                if 'encrypted' in st.session_state:
                    cipher_input = st.text_area(
                        "Şifreli Veri (Liste formatında)",
                        value=str(st.session_state['encrypted']),
                        height=100,
                        key="decrypt_input"
                    )
                else:
                    cipher_input = st.text_area(
                        "Şifreli Veri (Liste formatında)",
                        value="[]",
                        height=100,
                        key="decrypt_input",
                        help="Örn: [1234, 5678, 9012]"
                    )

                if st.button("🔓 Çöz", use_container_width=True, type="secondary"):
                    try:
                        # String'i listeye çevir
                        encrypted_list = eval(cipher_input)
                        if isinstance(encrypted_list, list) and all(isinstance(x, int) for x in encrypted_list):
                            decrypted = decrypt_message(encrypted_list, d, n)
                            st.success("✅ Mesaj başarıyla çözüldü!")

                            # Çözme detay tablosu
                            st.markdown("##### 📋 Adım Adım Çözme")
                            table_html = """
                            <table class="crypto-table">
                                <tr>
                                    <th>Şifreli (c)</th>
                                    <th>c^d mod n</th>
                                    <th>ASCII (m)</th>
                                    <th>Karakter</th>
                                </tr>
                            """
                            for c in encrypted_list:
                                m = decrypt_char(c, d, n)
                                char = chr(m) if 32 <= m <= 126 else '?'
                                table_html += f"""
                                <tr>
                                    <td><code>{c}</code></td>
                                    <td>{c}^{d} mod {n}</td>
                                    <td>{m}</td>
                                    <td><strong>{char}</strong></td>
                                </tr>
                                """
                            table_html += "</table>"
                            st.markdown(table_html, unsafe_allow_html=True)

                            # Çözülmüş metin
                            st.markdown("##### 📝 Çözülmüş Metin")
                            st.success(f"**{decrypted}**")
                        else:
                            st.error("Geçersiz format. Tam sayı listesi girin.")
                    except Exception as ex:
                        st.error(f"Hata: {ex}")

    # =====================================================================
    # SEKME 2: GÜVENLİK ANALİZİ
    # =====================================================================
    with tab2:
        st.markdown("### 🛡️ Güvenlik Laboratuvarı")
        st.markdown("""
        <div class="info-card">
            <strong>📖 RSA Güvenliği Hakkında</strong><br><br>
            RSA'nın güvenliği, büyük iki asal sayının çarpımını (<code>n = p × q</code>) 
            çarpanlarına ayırmanın hesaplama açısından çok zor olmasına dayanır.
            Bu bölümde, farklı anahtar uzunlukları için brute-force saldırı simülasyonu 
            yaparak bu zorluğu gözlemleyebilirsiniz.
        </div>
        """, unsafe_allow_html=True)

        col_attack1, col_attack2 = st.columns([1, 1])

        with col_attack1:
            st.markdown("#### 🔓 Tek Anahtar Saldırısı")
            st.markdown("""
            Mevcut anahtarınıza brute-force saldırı yapın ve kırılma süresini gözlemleyin.
            """)

            if keys_ready:
                n_val = st.session_state['n']
                n_bits = n_val.bit_length()

                st.markdown(f"""
                - **Hedef n**: `{n_val}`
                - **Bit uzunluğu**: `{n_bits} bit`
                """)

                if st.button("⚔️ Saldırıyı Başlat", use_container_width=True, type="primary"):
                    with st.spinner("Brute-force saldırısı yapılıyor..."):
                        p_found, q_found, elapsed = brute_force_factor(n_val)

                    st.success(f"🔓 **Anahtar kırıldı!** Süre: **{elapsed:.6f}** saniye")
                    st.markdown(f"""
                    - **Bulunan p**: `{p_found}`
                    - **Bulunan q**: `{q_found}`
                    - **Doğrulama**: `{p_found} × {q_found} = {p_found * q_found}`
                    """)

                    if p_found * q_found == n_val:
                        st.balloons()
            else:
                st.info("⬅️ Önce sidebar'dan anahtar oluşturun.")

        with col_attack2:
            st.markdown("#### 📊 Zaman Karmaşıklığı Analizi")
            st.markdown("""
            Farklı bit uzunlukları için kırma süresini ölçerek 
            üstel artışı gözlemleyin.
            """)

            # Analiz parametreleri
            bit_range = st.multiselect(
                "Test edilecek bit uzunlukları",
                options=[8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 36, 40],
                default=[8, 12, 16, 20, 24, 28, 32],
                help="Yüksek değerler uzun sürebilir!"
            )

            num_trials = st.slider(
                "Her uzunluk için deneme sayısı",
                min_value=1, max_value=10, value=3,
                help="Sonuçların ortalaması alınır"
            )

            if st.button("📈 Analizi Başlat", use_container_width=True, type="primary"):
                if bit_range:
                    bit_range_sorted = sorted(bit_range)
                    results = []
                    progress_bar = st.progress(0, text="Analiz başlıyor...")

                    for idx, bits in enumerate(bit_range_sorted):
                        times = []
                        for trial in range(num_trials):
                            # Her deneme için yeni asal çifti üret
                            test_p = generate_prime(bits)
                            test_q = generate_prime(bits)
                            while test_q == test_p:
                                test_q = generate_prime(bits)
                            test_n = test_p * test_q

                            # Saldırı süresini ölç
                            _, _, elapsed = brute_force_factor(test_n)
                            times.append(elapsed)

                        avg_time = np.mean(times)
                        results.append({
                            'bits': bits,
                            'avg_time': avg_time,
                            'n_bits': bits * 2,  # n yaklaşık 2*bits uzunluğunda
                            'min_time': min(times),
                            'max_time': max(times)
                        })

                        progress = (idx + 1) / len(bit_range_sorted)
                        progress_bar.progress(progress, text=f"Test ediliyor: {bits} bit ({idx + 1}/{len(bit_range_sorted)})")

                    progress_bar.progress(1.0, text="✅ Analiz tamamlandı!")

                    # Plotly ile çizgi grafiği oluştur
                    fig = go.Figure()

                    # Ortalama süre çizgisi
                    fig.add_trace(go.Scatter(
                        x=[r['bits'] for r in results],
                        y=[r['avg_time'] for r in results],
                        mode='lines+markers',
                        name='Ortalama Kırma Süresi',
                        line=dict(color='#6C63FF', width=3),
                        marker=dict(size=10, symbol='circle',
                                    line=dict(color='#FFFFFF', width=2)),
                        hovertemplate='<b>%{x} bit</b><br>Süre: %{y:.6f} s<extra></extra>'
                    ))

                    # Min-Max aralığı
                    fig.add_trace(go.Scatter(
                        x=[r['bits'] for r in results] + [r['bits'] for r in results][::-1],
                        y=[r['max_time'] for r in results] + [r['min_time'] for r in results][::-1],
                        fill='toself',
                        fillcolor='rgba(108, 99, 255, 0.15)',
                        line=dict(color='rgba(108, 99, 255, 0)'),
                        name='Min-Max Aralığı',
                        hoverinfo='skip'
                    ))

                    fig.update_layout(
                        title=dict(
                            text='🔓 Brute-Force Kırma Süresi vs Anahtar Uzunluğu',
                            font=dict(size=18, color='#E2E8F0')
                        ),
                        xaxis=dict(
                            title='Asal Sayı Bit Uzunluğu (p ve q)',
                            titlefont=dict(size=14, color='#9CA3AF'),
                            tickfont=dict(color='#9CA3AF'),
                            gridcolor='#2D3748',
                            dtick=4
                        ),
                        yaxis=dict(
                            title='Kırma Süresi (saniye)',
                            titlefont=dict(size=14, color='#9CA3AF'),
                            tickfont=dict(color='#9CA3AF'),
                            gridcolor='#2D3748',
                            type='log'  # Logaritmik eksen
                        ),
                        plot_bgcolor='#0E1117',
                        paper_bgcolor='#0E1117',
                        font=dict(color='#E2E8F0'),
                        legend=dict(
                            bgcolor='rgba(26, 29, 35, 0.8)',
                            bordercolor='#2D3748',
                            font=dict(color='#E2E8F0')
                        ),
                        hovermode='x unified',
                        height=500
                    )

                    st.plotly_chart(fig, use_container_width=True)

                    # Sonuç tablosu
                    st.markdown("##### 📊 Detaylı Sonuçlar")
                    table_html = """
                    <table class="crypto-table">
                        <tr>
                            <th>p,q Bit Uzunluğu</th>
                            <th>n Bit Uzunluğu (≈)</th>
                            <th>Ort. Kırma Süresi</th>
                            <th>Min Süre</th>
                            <th>Max Süre</th>
                        </tr>
                    """
                    for r in results:
                        table_html += f"""
                        <tr>
                            <td>{r['bits']} bit</td>
                            <td>~{r['n_bits']} bit</td>
                            <td><code>{r['avg_time']:.6f} s</code></td>
                            <td>{r['min_time']:.6f} s</td>
                            <td>{r['max_time']:.6f} s</td>
                        </tr>
                        """
                    table_html += "</table>"
                    st.markdown(table_html, unsafe_allow_html=True)

                    # Sonuç analizi
                    if len(results) >= 2:
                        first = results[0]['avg_time']
                        last = results[-1]['avg_time']
                        if first > 0:
                            ratio = last / first
                            st.markdown(f"""
                            <div class="info-card">
                                <strong>📈 Analiz Sonucu</strong><br><br>
                                {results[0]['bits']} bit'ten {results[-1]['bits']} bit'e geçişte 
                                kırma süresi yaklaşık <strong>{ratio:.1f}x</strong> arttı.<br>
                                Bu, RSA'nın güvenliğinin anahtar uzunluğuyla <strong>üstel olarak</strong> 
                                arttığını göstermektedir.
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.warning("En az bir bit uzunluğu seçin.")

        # Ek güvenlik bilgisi
        st.markdown("---")
        st.markdown("""
        <div class="info-card">
            <strong>🔐 Gerçek Dünyada RSA Güvenliği</strong><br><br>
            <table class="crypto-table">
                <tr><th>Anahtar Uzunluğu</th><th>Güvenlik Durumu</th><th>Kullanım Alanı</th></tr>
                <tr><td>512 bit</td><td><span class="security-low">Kırılmış</span></td><td>Artık kullanılmamalı</td></tr>
                <tr><td>1024 bit</td><td><span class="security-low">Zayıf</span></td><td>Eski sistemler</td></tr>
                <tr><td>2048 bit</td><td><span class="security-medium">Güvenli</span></td><td>Güncel standart</td></tr>
                <tr><td>4096 bit</td><td><span class="security-high">Çok Güvenli</span></td><td>Hassas veriler</td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    # =====================================================================
    # SEKME 3: MATEMATİKSEL ARKA PLAN
    # =====================================================================
    with tab3:
        st.markdown("### 📚 RSA Algoritmasının Matematiksel Temelleri")

        # 1. RSA Genel Bakış
        st.markdown("#### 1️⃣ RSA Algoritmasına Genel Bakış")
        st.markdown("""
        <div class="info-card">
            RSA (Rivest–Shamir–Adleman), 1977'de tanıtılmış bir <strong>açık anahtarlı şifreleme</strong> 
            (asymmetric encryption) algoritmasıdır. Güvenliği, büyük sayıların çarpanlarına ayrılmasının 
            hesaplama açısından zor olmasına dayanır (<em>Integer Factorization Problem</em>).
        </div>
        """, unsafe_allow_html=True)

        # 2. Anahtar Üretimi
        st.markdown("#### 2️⃣ Anahtar Üretim Süreci")

        st.markdown("**Adım 1:** İki büyük asal sayı seç: $p$ ve $q$")
        st.latex(r"p, q \in \mathbb{P} \quad \text{(asal sayılar kümesi)}")

        st.markdown("**Adım 2:** Modülü hesapla:")
        st.latex(r"n = p \times q")

        st.markdown("**Adım 3:** Euler'in Totient fonksiyonunu hesapla:")
        st.latex(r"\phi(n) = (p - 1)(q - 1)")

        st.markdown("""
        <div class="math-box">
            <strong>💡 Euler'in Totient Fonksiyonu</strong><br>
            φ(n), 1'den n'ye kadar olan ve n ile aralarında asal olan sayıların 
            adedini verir. İki asal sayının çarpımı için: φ(pq) = (p-1)(q-1)
        </div>
        """, unsafe_allow_html=True)

        st.markdown("**Adım 4:** Açık anahtar üssünü seç:")
        st.latex(r"1 < e < \phi(n) \quad \text{ve} \quad \gcd(e, \phi(n)) = 1")

        st.markdown("""
        > Genellikle $e = 65537 = 2^{16} + 1$ seçilir. Hem güvenli hem de
        > verimli olduğu kanıtlanmıştır (Fermat asalı).
        """)

        st.markdown("**Adım 5:** Özel anahtarı hesapla:")
        st.latex(r"d \equiv e^{-1} \pmod{\phi(n)}")
        st.latex(r"\text{yani: } e \cdot d \equiv 1 \pmod{\phi(n)}")

        st.markdown("""
        <div class="math-box">
            <strong>🔧 Genişletilmiş Öklid Algoritması</strong><br>
            d değeri, Genişletilmiş Öklid Algoritması kullanılarak hesaplanır.
            Bu algoritma, ax + by = gcd(a,b) denkleminin çözümlerini bulur.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # 3. Şifreleme ve Çözme
        st.markdown("#### 3️⃣ Şifreleme ve Çözme")

        col_enc, col_dec = st.columns(2)

        with col_enc:
            st.markdown("##### 🔒 Şifreleme (Encryption)")
            st.latex(r"c = m^e \mod n")
            st.markdown("""
            - $m$: Düz metin (plaintext) - ASCII değeri
            - $e$: Açık anahtar üssü
            - $n$: Modül
            - $c$: Şifreli metin (ciphertext)
            """)

        with col_dec:
            st.markdown("##### 🔓 Çözme (Decryption)")
            st.latex(r"m = c^d \mod n")
            st.markdown("""
            - $c$: Şifreli metin
            - $d$: Özel anahtar üssü
            - $n$: Modül
            - $m$: Orijinal metin
            """)

        st.markdown("---")

        # 4. Doğrulama
        st.markdown("#### 4️⃣ Neden Çalışıyor? (Euler Teoremi)")

        st.latex(r"m^{e \cdot d} \equiv m^{1 + k\phi(n)} \equiv m \cdot (m^{\phi(n)})^k \equiv m \cdot 1^k \equiv m \pmod{n}")

        st.markdown("""
        <div class="info-card">
            <strong>📐 Euler Teoremi</strong><br><br>
            Eğer <code>gcd(m, n) = 1</code> ise:
        </div>
        """, unsafe_allow_html=True)
        st.latex(r"m^{\phi(n)} \equiv 1 \pmod{n}")

        st.markdown("""
        Bu teorem sayesinde, $e \\cdot d \\equiv 1 \\pmod{\\phi(n)}$ olduğunda,
        şifreleme ve çözme işlemlerinin birbirini tersine çevirdiği 
        matematiksel olarak kanıtlanmıştır.
        """)

        st.markdown("---")

        # 5. Modüler Aritmetik
        st.markdown("#### 5️⃣ Modüler Aritmetik Temelleri")

        st.markdown("**Modüler Toplama:**")
        st.latex(r"(a + b) \mod n = ((a \mod n) + (b \mod n)) \mod n")

        st.markdown("**Modüler Çarpma:**")
        st.latex(r"(a \times b) \mod n = ((a \mod n) \times (b \mod n)) \mod n")

        st.markdown("**Modüler Üs Alma (Square-and-Multiply):**")
        st.latex(r"a^b \mod n \quad \text{→ Python: } \texttt{pow(a, b, n)}")

        st.markdown("""
        <div class="math-box">
            <strong>⚡ Verimli Modüler Üs Alma</strong><br>
            Python'un <code>pow(base, exp, mod)</code> fonksiyonu, "square-and-multiply" 
            algoritmasını kullanarak büyük sayılar için bile hızlı modüler üs alma yapar.
            Zaman karmaşıklığı: O(log(exp))
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # 6. Güvenlik Analizi
        st.markdown("#### 6️⃣ Hesaplama Zorluğu (Computational Hardness)")

        st.markdown("""
        <div class="info-card">
            <strong>🔐 RSA Güvenliğinin Temeli</strong><br><br>
            RSA'nın güvenliği şu probleme dayanır:<br><br>
            <em>"n = p × q verildiğinde, p ve q'yu bulmak hesaplama açısından zordur."</em>
            <br><br>
            Bu, <strong>Tamsayı Çarpanlarına Ayırma Problemi</strong> 
            (Integer Factorization Problem) olarak bilinir.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("**Brute-Force saldırının zaman karmaşıklığı:**")
        st.latex(r"T(n) = O(\sqrt{n}) = O(2^{b/2})")
        st.markdown("Burada $b$, $n$'in bit uzunluğudur.")

        st.markdown("**Örnek karmaşıklık tablosu:**")

        complexity_data = {
            "Bit Uzunluğu (b)": [32, 64, 128, 256, 512, 1024, 2048],
            "Deneme Sayısı (≈2^(b/2))": ["65K", "4.3B", "1.8×10¹⁹", "3.4×10³⁸", "1.2×10⁷⁷", "1.3×10¹⁵⁴", "1.8×10³⁰⁸"],
            "Süre (1GHz CPU)": ["~65 µs", "~4.3 s", "~570 yıl", "~10³¹ yıl", "~10⁷⁰ yıl", "~10¹⁴⁷ yıl", "~10³⁰¹ yıl"]
        }

        st.table(complexity_data)

        st.markdown("""
        <div class="info-card">
            <strong>📌 Sonuç</strong><br><br>
            Anahtar uzunluğu arttıkça, kırma süresi <strong>üstel olarak</strong> artar.
            Bu, RSA'yı yeterli anahtar uzunluğu ile pratik olarak kırılamaz kılar.
            Günümüzde minimum <strong>2048 bit</strong> anahtar uzunluğu önerilmektedir.
        </div>
        """, unsafe_allow_html=True)

        # Mevcut anahtarla interaktif örnek
        if keys_ready:
            st.markdown("---")
            st.markdown("#### 🔬 Mevcut Anahtarınızla İnteraktif Örnek")

            p_cur = st.session_state.get('current_p', 0)
            q_cur = st.session_state.get('current_q', 0)
            n_cur = st.session_state['n']
            phi_cur = st.session_state['phi_n']
            e_cur = st.session_state['e']
            d_cur = st.session_state['d']

            st.markdown(f"""
            **Sizin değerleriniz ile RSA adımları:**

            1. **Asal sayılar:** $p = {p_cur}$, $q = {q_cur}$

            2. **Modül:** $n = {p_cur} \\times {q_cur} = {n_cur}$

            3. **Euler Totient:** $\\phi(n) = ({p_cur} - 1)({q_cur} - 1) = {phi_cur}$

            4. **Açık anahtar üssü:** $e = {e_cur}$, $\\gcd({e_cur}, {phi_cur}) = {gcd(e_cur, phi_cur)}$ ✅

            5. **Özel anahtar:** $d = {d_cur}$, ${e_cur} \\times {d_cur} \\mod {phi_cur} = {(e_cur * d_cur) % phi_cur}$ ✅
            """)

            # Örnek şifreleme
            example_char = st.text_input("Bir karakter girin:", value="A", max_chars=1)
            if example_char:
                m_ex = ord(example_char)
                if m_ex < n_cur:
                    c_ex = encrypt_char(m_ex, e_cur, n_cur)
                    m_back = decrypt_char(c_ex, d_cur, n_cur)

                    st.markdown(f"""
                    **Adım adım şifreleme ve çözme:**

                    | İşlem | Formül | Sonuç |
                    |-------|--------|-------|
                    | Karakter → ASCII | `'{example_char}' → m` | $m = {m_ex}$ |
                    | Şifreleme | $c = {m_ex}^{{{e_cur}}} \\mod {n_cur}$ | $c = {c_ex}$ |
                    | Çözme | $m = {c_ex}^{{{d_cur}}} \\mod {n_cur}$ | $m = {m_back}$ |
                    | ASCII → Karakter | `m → '{chr(m_back)}'` | ✅ Doğru! |
                    """)
                else:
                    st.warning(f"ASCII değeri ({m_ex}) modül n ({n_cur}) değerinden büyük. Daha büyük asal sayılar seçin.")

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #6B7280; padding: 1rem;">
        <p>🔐 RSA Şifreleme Laboratuvarı | Eğitim Amaçlı</p>
        <p style="font-size: 0.8rem;">
            Bu uygulama eğitim amaçlıdır. Gerçek şifreleme için <code>cryptography</code> 
            gibi güvenilir kütüphaneler kullanın.
        </p>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
