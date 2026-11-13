#!/usr/bin/env python3
"""
RSA Fermat Factorization Solver
--------------------------------
n, e, c qiymatlarini kiritsangiz, agar p va q (n ning tub ko'paytuvchilari)
bir-biriga yaqin bo'lsa, bu skript avtomatik ravishda:
  1) n ni Fermat usuli bilan faktorlaydi (p, q ni topadi)
  2) RSA yopiq kalitini (d) hisoblaydi
  3) shifrmatn c ni ochib, ochiq matn m ni chiqaradi

Ishlatish:
    python3 rsa_fermat_solver.py
(so'ralganda n, e, c qiymatlarini kiriting)

Yoki skript ichida pastdagi N, E, C o'zgaruvchilariga
to'g'ridan-to'g'ri qiymat berib ham ishlatsa bo'ladi.
"""

import math
import sys


def fermat_factor(n: int, max_iter: int = 5_000_000, progress_every: int = 200_000):
    """
    n = p * q bo'lib, p va q bir-biriga yaqin bo'lsa,
    Fermat usuli bilan tezda (soniyalar ichida) p va q ni topadi.

    G'oyasi: n = a^2 - b^2 = (a-b)(a+b) ko'rinishida yozish mumkin,
    bunda a = sqrt(n) dan boshlab yuqoriga qarab qidiriladi.
    """
    a = math.isqrt(n) + 1
    for i in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            return p, q, i
        a += 1
        if progress_every and i % progress_every == 0 and i > 0:
            print(f"  [..] {i}-urinish, hali topilmadi", file=sys.stderr)
    return None, None, max_iter


def rsa_decrypt(n: int, e: int, c: int, p: int, q: int) -> int:
    """p, q ma'lum bo'lganda standart RSA deshifrlash: m = c^d mod n."""
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)          # e ning phi bo'yicha teskari elementi (yopiq kalit)
    m = pow(c, d, n)             # ochiq matnni tiklash
    return m


def int_to_bytes(m: int) -> bytes:
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, byteorder="big")


def solve(n: int, e: int, c: int):
    print("[*] n ni Fermat usuli bilan faktorlashga urinilmoqda...")
    p, q, iters = fermat_factor(n)

    if p is None:
        print("[-] Fermat usuli ishlamadi — p va q yetarlicha yaqin emas.")
        print("    (Boshqa usul kerak: Pollard's rho, Wiener attack va h.k.)")
        return None

    print(f"[+] Faktorlar topildi ({iters}-urinishda):")
    print(f"    p = {p}")
    print(f"    q = {q}")
    assert p * q == n, "Xatolik: p * q != n"

    m = rsa_decrypt(n, e, c, p, q)
    raw = int_to_bytes(m)

    print(f"\n[+] m (butun son) = {m}")
    print(f"[+] m (baytlarda)  = {raw}")

    try:
        text = raw.decode("utf-8")
        print(f"[+] m (matn sifatida) = {text}")
    except UnicodeDecodeError:
        print("[-] Baytlarni UTF-8 matn sifatida o'qib bo'lmadi (raw baytlarga qarang).")

    return m


def main():
    # --- Agar qiymatlarni to'g'ridan-to'g'ri kodga yozmoqchi bo'lsangiz,
    #     shu joyga qo'ying va pastdagi input() qatorlarini izohga oling ---
    N = None
    E = None
    C = None

    if N is None:
        N = int(input("n = ").strip())
    if E is None:
        E = int(input("e = ").strip())
    if C is None:
        C = int(input("c = ").strip())

    solve(N, E, C)


if __name__ == "__main__":
    main()
