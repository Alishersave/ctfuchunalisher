#!/usr/bin/env python3
"""
Elliptik Egri Chiziq (ECDLP) + AES-CBC Solver
-----------------------------------------------
Kichik maydonli (p ~ bir necha milliard) elliptik egri chiziqqa asoslangan
"weak ECC" CTF topshiriqlari uchun.

Egri chiziq:  y^2 = x^3 + a*x + b (mod p)
Berilgan:     G (bazaviy nuqta), P = n*G (ochiq kalit)
Topiladigan:  n (maxfiy skalyar)

So'ng:        AES-128-CBC kaliti = SHA256(str(n))[:16] deb faraz qilinadi
              (bu ko'p CTF'larda ishlatiladigan oddiy kalit hosil qilish usuli;
               agar ishlamasa, pastdagi KEY_CANDIDATES ro'yxatini kengaytiring)

Ishlatish:
    python3 ecc_solver.py
(so'ralganda p, a, b, G, P, iv, ct qiymatlarini kiriting)
"""

import math
import re
import hashlib
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


# ============ ELLIPTIK EGRI CHIZIQ ARIFMETIKASI ============

class Curve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

    def on_curve(self, pt):
        if pt is None:
            return True
        x, y = pt
        return (y * y - (x**3 + self.a * x + self.b)) % self.p == 0

    def _inv(self, x):
        return pow(x, self.p - 2, self.p)

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # cheksizlik nuqtasi
        if p1 == p2:
            lam = (3 * x1 * x1 + self.a) * self._inv(2 * y1) % self.p
        else:
            lam = (y2 - y1) * self._inv(x2 - x1) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def neg(self, pt):
        if pt is None:
            return None
        x, y = pt
        return (x, (-y) % self.p)

    def mul(self, k, pt):
        result = None
        addend = pt
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result


# ============ BABY-STEP GIANT-STEP (ECDLP YECHISH) ============

def bsgs_ecdlp(curve, G, P, verbose=True):
    """
    n topadi, shunday qilib n*G = P bo'ladi.
    Hasse chegarasidan foydalanib qidiruv oralig'ini cheklaydi:
        order ~ p + 1 +/- 2*sqrt(p)
    """
    p = curve.p
    M = p + 2 * math.isqrt(p) + 2
    m = math.isqrt(M) + 1

    if verbose:
        print(f"[*] BSGS qadam kattaligi m = {m}")

    # Baby steps: barcha j*G ni jadvalga saqlaymiz (j = 0..m-1)
    baby = {}
    cur = None
    for j in range(m):
        baby[cur] = j
        cur = curve.add(cur, G)

    # Giant steps: P - i*m*G ni baby jadvalida qidiramiz
    mG = curve.mul(m, G)
    neg_mG = curve.neg(mG)

    giant = P
    for i in range(m):
        if giant in baby:
            n = i * m + baby[giant]
            if verbose:
                print(f"[+] n topildi: {n}")
            return n
        giant = curve.add(giant, neg_mG)

    return None


# ============ AES-CBC DESHIFRLASH ============

def aes_cbc_decrypt(key, iv, ct):
    if not HAVE_CRYPTO:
        raise RuntimeError("'cryptography' kutubxonasi topilmadi (pip install cryptography)")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    d = cipher.decryptor()
    return d.update(ct) + d.finalize()


def strip_pkcs7(data):
    """PKCS7 padding to'g'ri bo'lsa, uni olib tashlaydi; aks holda xato qaytaradi."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding noto'g'ri (bu kalit ehtimol xato)")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding mos kelmadi (bu kalit ehtimol xato)")
    return data[:-pad_len]


def try_key_candidates(n, iv, ct, extra_candidates=None):
    """
    Turli xil kalit hosil qilish usullarini sinab ko'radi.
    Muvaffaqiyatli (to'g'ri PKCS7 padding bilan) natijani qaytaradi.
    """
    candidates = {
        "SHA256(str(n))[:16]": hashlib.sha256(str(n).encode()).digest()[:16],
        "SHA256(str(n)) (32 bayt, AES-256)": hashlib.sha256(str(n).encode()).digest(),
        "SHA256(n bytes4)[:16]": hashlib.sha256(n.to_bytes(4, 'big')).digest()[:16],
        "MD5(str(n))": hashlib.md5(str(n).encode()).digest(),
    }
    if extra_candidates:
        candidates.update(extra_candidates)

    for label, key in candidates.items():
        try:
            raw = aes_cbc_decrypt(key, iv, ct)
            pt = strip_pkcs7(raw)
            if pt.isascii() and pt.decode().isprintable():
                print(f"[+] MOS KEY TOPILDI -> {label}")
                return pt.decode()
        except Exception:
            continue
    return None


# ============ ASOSIY OQIM ============

def solve(p, a, b, G, P, iv_hex, ct_hex):
    curve = Curve(p, a, b)

    print("[*] Nuqtalar egri chiziqda ekanini tekshirish...")
    assert curve.on_curve(G), "G egri chiziqda emas!"
    assert curve.on_curve(P), "P egri chiziqda emas!"
    print("    G va P to'g'ri.")

    print("[*] ECDLP yechilmoqda (BSGS)...")
    n = bsgs_ecdlp(curve, G, P)
    if n is None:
        print("[-] n topilmadi (qidiruv oralig'i yetarli emas bo'lishi mumkin).")
        return None

    check = curve.mul(n, G)
    print(f"[*] Tekshirish: n*G == P -> {check == P}")

    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)

    print("[*] AES-CBC kalitini turli usullar bilan sinab ko'rish...")
    flag = try_key_candidates(n, iv, ct)

    if flag:
        print(f"\n[+] FLAG: {flag}")
    else:
        print("[-] Hech qanday standart kalit usuli ishlamadi.")
        print("    try_key_candidates() ichidagi 'candidates' lug'atiga")
        print("    yangi kalit hosil qilish usulini qo'shib ko'ring.")

    return flag


def read_int(prompt):
    """Faqat sonni oladi, boshqa hamma narsani (bo'shliq, matn) e'tiborsiz qoldiradi."""
    line = input(prompt)
    nums = re.findall(r"-?\d+", line)
    if not nums:
        raise ValueError(f"'{line}' ichida son topilmadi")
    return int(nums[0])


def read_point(prompt):
    """
    Nuqtani har qanday formatda qabul qiladi:
    '235022692, 1987849435'  yoki  '(235022692, 1987849435)'
    yoki  'G = (235022692, 1987849435)'  yoki  '235022692 1987849435'
    """
    line = input(prompt)
    nums = re.findall(r"-?\d+", line)
    if len(nums) < 2:
        raise ValueError(f"'{line}' ichidan ikkita son (x, y) topilmadi")
    return (int(nums[0]), int(nums[1]))


def read_hex(prompt):
    """Hex qatorni oladi — probel, '0x' prefiksi va boshqa belgilarni tozalaydi."""
    line = input(prompt).strip()
    line = line.replace("0x", "").replace(" ", "").replace("\t", "")
    return line


def main():
    try:
        p = read_int("p = ")
        a = read_int("a = ")
        b = read_int("b = ")
        G = read_point("G (masalan: 235022692, 1987849435  yoki  (235022692, 1987849435)) = ")
        P = read_point("P (xuddi shu formatda) = ")
        iv_hex = read_hex("iv (hex) = ")
        ct_hex = read_hex("ct (hex) = ")
    except ValueError as e:
        print(f"[-] Kiritishda xato: {e}")
        print("    Iltimos, qiymatlarni qayta kiriting.")
        sys.exit(1)

    if not HAVE_CRYPTO:
        print("[!] 'cryptography' kutubxonasi topilmadi.")
        print("    O'rnatish uchun: pip install cryptography")
        print("    (ECDLP n'ni baribir topib beraman, lekin AES deshifrlash ishlamaydi)")

    solve(p, a, b, G, P, iv_hex, ct_hex)


if __name__ == "__main__":
    main()
