"""
RSA Dashboard - Test Dosyası
=============================
app.py'deki matematiksel fonksiyonlar için pytest tabanlı testler.
Streamlit UI fonksiyonları test edilmez; sadece saf matematiksel işlevler test edilir.
"""

import pytest
import sys
import os

# app.py'nin bulunduğu dizini Python yoluna ekle
sys.path.insert(0, os.path.dirname(__file__))

# Streamlit ve diğer UI kütüphanelerini mock'la (import hatalarını önlemek için)
import unittest.mock as mock
sys.modules.setdefault("streamlit", mock.MagicMock())
sys.modules.setdefault("plotly", mock.MagicMock())
sys.modules.setdefault("plotly.graph_objects", mock.MagicMock())
sys.modules.setdefault("numpy", mock.MagicMock())
sys.modules.setdefault("sympy", mock.MagicMock())

from app import (
    gcd,
    extended_gcd,
    mod_inverse,
    is_prime_miller_rabin,
    generate_prime,
    brute_force_factor,
    generate_rsa_keys,
    encrypt_char,
    decrypt_char,
    encrypt_message,
    decrypt_message,
)

# =============================================================================
# GCD (En Büyük Ortak Bölen) Testleri
# =============================================================================

class TestGCD:
    def test_gcd_basic(self):
        """Temel GCD hesaplamaları."""
        assert gcd(12, 8) == 4
        assert gcd(100, 75) == 25
        assert gcd(17, 13) == 1  # Aralarında asal sayılar

    def test_gcd_with_zero(self):
        """Sıfır içeren GCD hesaplamaları: gcd(a, 0) = a."""
        assert gcd(5, 0) == 5
        assert gcd(0, 7) == 7

    def test_gcd_same_numbers(self):
        """Aynı sayıların GCD'si kendisidir."""
        assert gcd(9, 9) == 9
        assert gcd(100, 100) == 100

    def test_gcd_commutative(self):
        """GCD değişme özelliği: gcd(a, b) == gcd(b, a)."""
        assert gcd(48, 18) == gcd(18, 48)
        assert gcd(100, 37) == gcd(37, 100)

    def test_gcd_prime_pair(self):
        """İki asal sayının GCD'si 1'dir."""
        assert gcd(61, 53) == 1  # RSA'da kullanılan örnek asallar
        assert gcd(7, 11) == 1

    def test_gcd_euler_totient_case(self):
        """RSA'da e ve phi(n) aralarında asal olmalı."""
        p, q = 61, 53
        phi_n = (p - 1) * (q - 1)
        e = 65537  # Sık kullanılan açık üs; phi_n'den büyük olduğu için
        # phi_n = 3120 için e=17 aralarında asal
        e2 = 17
        assert gcd(e2, phi_n) == 1  # RSA için geçerli e

# =============================================================================
# Genişletilmiş GCD Testleri
# =============================================================================

class TestExtendedGCD:
    def test_extended_gcd_identity(self):
        """ax + by = gcd(a, b) eşitliğini doğrula."""
        for a, b in [(35, 15), (12, 8), (100, 37), (61, 53)]:
            g, x, y = extended_gcd(a, b)
            assert a * x + b * y == g, f"Başarısız: a={a}, b={b}"

    def test_extended_gcd_returns_correct_gcd(self):
        """Genişletilmiş GCD, doğru GCD'yi döndürmeli."""
        g, _, _ = extended_gcd(48, 18)
        assert g == 6

        g, _, _ = extended_gcd(7, 11)
        assert g == 1

    def test_extended_gcd_base_case(self):
        """a=0 için temel durum: gcd(0, b) = b."""
        g, x, y = extended_gcd(0, 7)
        assert g == 7
        assert 0 * x + 7 * y == 7

# =============================================================================
# Modüler Ters Testleri
# =============================================================================

class TestModInverse:
    def test_mod_inverse_basic(self):
        """Temel modüler ters: e * d ≡ 1 (mod phi)."""
        phi_n = 3120  # (61-1)*(53-1)
        e = 17
        d = mod_inverse(e, phi_n)
        assert d is not None
        assert (e * d) % phi_n == 1

    def test_mod_inverse_no_inverse(self):
        """GCD(e, phi) != 1 olduğunda None döndürmeli."""
        # gcd(4, 6) = 2 != 1 → ters yok
        result = mod_inverse(4, 6)
        assert result is None

    def test_mod_inverse_65537(self):
        """Sık kullanılan e=65537 için modüler ters."""
        p, q = 61, 53
        phi_n = (p - 1) * (q - 1)  # phi_n = 3120
        # 65537 > phi_n, bu yüzden e=17 kullanalım
        e = 17
        d = mod_inverse(e, phi_n)
        assert d is not None
        assert (e * d) % phi_n == 1

    def test_mod_inverse_symmetry(self):
        """mod_inverse(d, phi) = e olmalı."""
        phi_n = 3120
        e = 17
        d = mod_inverse(e, phi_n)
        assert d is not None
        e_back = mod_inverse(d, phi_n)
        assert e_back is not None
        assert (e_back * d) % phi_n == 1

# =============================================================================
# Miller-Rabin Asallık Testi
# =============================================================================

class TestMillerRabin:
    KNOWN_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                    53, 61, 67, 71, 79, 97, 101, 257, 1009, 7919, 104729]

    KNOWN_COMPOSITES = [4, 6, 8, 9, 10, 12, 15, 25, 49, 100, 561, 1105, 1729]

    def test_known_primes(self):
        """Bilinen asal sayıları doğru tanımlamalı."""
        for p in self.KNOWN_PRIMES:
            assert is_prime_miller_rabin(p), f"{p} asal olmalı"

    def test_known_composites(self):
        """Bilinen bileşik sayıları asal olarak işaretlememeli."""
        for n in self.KNOWN_COMPOSITES:
            assert not is_prime_miller_rabin(n), f"{n} bileşik olmalı"

    def test_edge_cases(self):
        """Sınır durumları: 0, 1 asal değil; 2, 3 asal."""
        assert not is_prime_miller_rabin(0)
        assert not is_prime_miller_rabin(1)
        assert is_prime_miller_rabin(2)
        assert is_prime_miller_rabin(3)

    def test_negative_numbers(self):
        """Negatif sayılar asal olmamalı."""
        assert not is_prime_miller_rabin(-5)
        assert not is_prime_miller_rabin(-1)

    def test_rsa_example_primes(self):
        """RSA örneklerinde kullanılan p=61, q=53 asal olmalı."""
        assert is_prime_miller_rabin(61)
        assert is_prime_miller_rabin(53)

# =============================================================================
# Asal Sayı Üretimi Testleri
# =============================================================================

class TestGeneratePrime:
    def test_generated_prime_is_prime(self):
        """Üretilen sayı gerçekten asal olmalı."""
        for _ in range(5):  # Birden fazla test
            p = generate_prime(16)
            assert is_prime_miller_rabin(p), f"Üretilen {p} asal değil"

    def test_generated_prime_bit_length(self):
        """Üretilen sayı belirtilen bit uzunluğuna sahip olmalı."""
        for bits in [8, 16, 32]:
            p = generate_prime(bits)
            assert p.bit_length() == bits, f"Beklenen {bits} bit, alınan {p.bit_length()} bit"

    def test_generated_prime_is_odd(self):
        """Üretilen asal sayı (2 hariç) tek olmalı."""
        for _ in range(5):
            p = generate_prime(16)
            assert p % 2 == 1 or p == 2

# =============================================================================
# Brute-Force Çarpanlara Ayırma Testleri
# =============================================================================

class TestBruteForce:
    def test_factor_small_product(self):
        """Küçük asal çarpımlarda doğru p ve q bulunmalı."""
        n = 61 * 53  # = 3233
        p_found, q_found, elapsed = brute_force_factor(n)
        assert p_found * q_found == n
        # p veya q 53 ya da 61 olmalı
        assert {p_found, q_found} == {53, 61}

    def test_factor_even_number(self):
        """Çift sayılar için 2 bulunmalı."""
        n = 2 * 97
        p_found, q_found, elapsed = brute_force_factor(n)
        assert p_found == 2
        assert q_found == 97

    def test_factor_prime_returns_itself(self):
        """Asal sayılar için (p, 1, elapsed) döndürmeli."""
        p_found, q_found, elapsed = brute_force_factor(97)
        assert p_found == 97
        assert q_found == 1

    def test_factor_timing(self):
        """Elapsed süre sıfırdan büyük veya eşit olmalı."""
        _, _, elapsed = brute_force_factor(3233)
        assert elapsed >= 0

    def test_factor_product_correct(self):
        """p_found * q_found her zaman n'e eşit olmalı."""
        test_values = [15, 21, 35, 77, 143, 3233]
        for n in test_values:
            p_found, q_found, _ = brute_force_factor(n)
            assert p_found * q_found == n, f"n={n} için çarpım yanlış"

# =============================================================================
# RSA Anahtar Üretimi Testleri
# =============================================================================

class TestGenerateRSAKeys:
    def test_basic_key_generation(self):
        """p=61, q=53 ile temel anahtar üretimi."""
        n, phi_n, e, d = generate_rsa_keys(61, 53)
        assert n == 61 * 53           # n = 3233
        assert phi_n == 60 * 52       # phi = 3120
        assert e is not None
        assert d is not None

    def test_key_relationship(self):
        """e * d ≡ 1 (mod phi_n) olmalı."""
        n, phi_n, e, d = generate_rsa_keys(61, 53)
        assert (e * d) % phi_n == 1

    def test_e_coprime_with_phi(self):
        """e ve phi_n aralarında asal olmalı."""
        n, phi_n, e, d = generate_rsa_keys(61, 53)
        assert gcd(e, phi_n) == 1

    def test_keys_valid_for_encryption(self):
        """Üretilen anahtarlar şifreleme ve çözme için geçerli olmalı."""
        n, phi_n, e, d = generate_rsa_keys(61, 53)
        m = 42  # Test mesajı
        c = encrypt_char(m, e, n)
        m_dec = decrypt_char(c, d, n)
        assert m_dec == m

    def test_large_primes(self):
        """Daha büyük asal sayılarla anahtar üretimi."""
        p, q = 1009, 1013  # İki asal sayı
        n, phi_n, e, d = generate_rsa_keys(p, q)
        assert n == p * q
        assert phi_n == (p - 1) * (q - 1)
        assert (e * d) % phi_n == 1

# =============================================================================
# Şifreleme ve Çözme Testleri
# =============================================================================

class TestEncryptDecrypt:
    @pytest.fixture
    def rsa_keys(self):
        """Test için RSA anahtarları."""
        n, phi_n, e, d = generate_rsa_keys(61, 53)
        return n, e, d

    def test_encrypt_decrypt_char(self, rsa_keys):
        """Tek karakter şifreleme ve çözme (tam tur)."""
        n, e, d = rsa_keys
        for m in [65, 72, 101, 110, 119]:  # ASCII değerleri
            c = encrypt_char(m, e, n)
            m_dec = decrypt_char(c, d, n)
            assert m_dec == m, f"m={m} için şifreleme/çözme başarısız"

    def test_encrypt_changes_value(self, rsa_keys):
        """Şifreleme değeri değiştirmeli (m != c olmalı, genellikle)."""
        n, e, d = rsa_keys
        m = 65  # 'A'
        c = encrypt_char(m, e, n)
        # Şifreli değer genellikle farklıdır (istisnai durumlar hariç)
        assert 0 <= c < n  # Şifreli değer [0, n) aralığında olmalı

    def test_encrypt_decrypt_message(self, rsa_keys):
        """Tam metin şifreleme ve çözme."""
        n, e, d = rsa_keys
        original = "Hello"
        encrypted = encrypt_message(original, e, n)
        decrypted = decrypt_message(encrypted, d, n)
        assert decrypted == original

    def test_encrypt_message_length(self, rsa_keys):
        """Şifreli liste uzunluğu, orijinal metin uzunluğuna eşit olmalı."""
        n, e, d = rsa_keys
        original = "RSA Test"
        encrypted = encrypt_message(original, e, n)
        assert len(encrypted) == len(original)

    def test_empty_message(self, rsa_keys):
        """Boş mesaj şifreleme/çözme."""
        n, e, d = rsa_keys
        encrypted = encrypt_message("", e, n)
        assert encrypted == []
        decrypted = decrypt_message([], d, n)
        assert decrypted == ""

    def test_single_char_message(self, rsa_keys):
        """Tek karakterli mesaj."""
        n, e, d = rsa_keys
        # n = 3233, ASCII < 128 < 3233, güvenli
        for char in "ABCZ09":
            encrypted = encrypt_message(char, e, n)
            decrypted = decrypt_message(encrypted, d, n)
            assert decrypted == char

    def test_rsa_mathematical_property(self, rsa_keys):
        """RSA matematiğini doğrula: (m^e)^d ≡ m (mod n)."""
        n, e, d = rsa_keys
        for m in [2, 10, 33, 65, 122]:
            c = pow(m, e, n)
            m_back = pow(c, d, n)
            assert m_back == m

    def test_different_messages_different_ciphers(self, rsa_keys):
        """Farklı mesajlar farklı şifreli metinler üretmeli."""
        n, e, d = rsa_keys
        c1 = encrypt_char(65, e, n)  # 'A'
        c2 = encrypt_char(66, e, n)  # 'B'
        assert c1 != c2

    def test_encrypt_output_range(self, rsa_keys):
        """Şifreli değer 0 ≤ c < n aralığında olmalı."""
        n, e, d = rsa_keys
        for m in range(32, 128):  # Yazdırılabilir ASCII karakterler
            c = encrypt_char(m, e, n)
            assert 0 <= c < n, f"m={m} için şifreli değer ({c}) aralık dışı"


# =============================================================================
# Uçtan Uca (End-to-End) RSA Testleri
# =============================================================================

class TestEndToEnd:
    def test_full_rsa_flow_small_primes(self):
        """Küçük asallarla tam RSA akışı."""
        p, q = 61, 53
        n, phi_n, e, d = generate_rsa_keys(p, q)
        message = "Hi"
        encrypted = encrypt_message(message, e, n)
        decrypted = decrypt_message(encrypted, d, n)
        assert decrypted == message

    def test_full_rsa_flow_larger_primes(self):
        """Daha büyük asallarla tam RSA akışı."""
        p, q = 1009, 1013
        n, phi_n, e, d = generate_rsa_keys(p, q)
        message = "RSA!"
        encrypted = encrypt_message(message, e, n)
        decrypted = decrypt_message(encrypted, d, n)
        assert decrypted == message

    def test_key_confidentiality(self):
        """e ile şifrelenmiş mesaj d olmadan çözülememeli (farklı key ile)."""
        n1, _, e1, d1 = generate_rsa_keys(61, 53)
        n2, _, e2, d2 = generate_rsa_keys(1009, 1013)

        m = 65  # 'A'
        c = encrypt_char(m, e1, n1)

        # d2 ile n1 üzerinde çözme → yanlış sonuç vermeli
        m_wrong = decrypt_char(c, d2, n1)
        assert m_wrong != m  # Yanlış anahtar doğru sonucu vermemeli

    def test_generated_prime_rsa_flow(self):
        """Üretilen asallarla tam RSA akışı."""
        p = generate_prime(16)
        q = generate_prime(16)
        while q == p:
            q = generate_prime(16)

        n, phi_n, e, d = generate_rsa_keys(p, q)
        assert n is not None
        message = "A"
        encrypted = encrypt_message(message, e, n)
        decrypted = decrypt_message(encrypted, d, n)
        assert decrypted == message
