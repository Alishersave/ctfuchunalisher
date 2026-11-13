#!/usr/bin/env python3
"""
Dynastic / Trithemius turidagi progressiv shifrni deshifrlash skripti.

Formula:
    dekodlangan_harf = (shifr_harf_qiymati - pozitsiya) mod 26

Bu yerda:
    - pozitsiya har bir HARF uchun start dan boshlab step qadam bilan o'sadi
    - _  { } kabi belgilar HISOBGA OLINMAYDI (pozitsiya ularda o'smaydi)
      va ular natijada o'zgarmasdan, xuddi shu joyida qoladi

Foydalanish (interaktiv):
    python3 dynastic_decrypt.py

Yoki to'g'ridan-to'g'ri kodni o'zgartirib CIPHERTEXT, START, STEP,
SKIP_CHARS qiymatlarini pastda qo'lda kiritishingiz ham mumkin.
"""


def decrypt(ciphertext: str, start: int, step: int, skip_chars: str = "_{}") -> str:
    """
    ciphertext : shifrlangan matn
    start      : birinchi BELGI uchun pozitsiya qiymati (masalan 0, 1, 2, -1 ...)
    step       : har keyingi belgida pozitsiya qancha o'zgarishi (masalan +1, +2, -3, -4)
    skip_chars : shifrlanmaydigan (o'zgarmasdan qoladigan) belgilar,
                 lekin ular ham pozitsiya hisobiga KIRADI (asl Dynastic/Trithemius
                 algoritmi shunday ishlaydi: pozitsiya matndagi HAR BIR belgida
                 (bo'shliq, "_" va h.k. ham) bir xilda o'sib boradi)
    """
    result = []
    pos = start  # joriy pozitsiya (birinchi belgida shu qiymatdan boshlanadi)

    for ch in ciphertext:
        if ch in skip_chars or not ch.isalpha():
            # Bu belgi shifrlanmagan (yoki harf emas) -> o'zgarmasdan qoldiramiz.
            # DIQQAT: pastda pos baribir oshadi, chunki asl algoritmda pozitsiya
            # HAR BIR belgida (harf bo'lmasa ham) bir xilda ko'tariladi.
            result.append(ch)
        else:
            # Katta/kichik harfni aniqlab, mos baza belgisini tanlaymiz
            base = ord('A') if ch.isupper() else ord('a')
            # Asosiy formula: (shifr - pozitsiya) mod 26
            val = ord(ch) - base
            dec_val = (val - pos) % 26
            result.append(chr(dec_val + base))

        # Keyingi belgi uchun pozitsiyani step qadar oshiramiz (HAR DOIM, har belgida)
        pos += step

    return "".join(result)


def main():
    print("=== Dynastic / Trithemius deshifrlash vositasi ===\n")

    ciphertext = input("Shifrlangan matnni kiriting: ").strip()

    start = int(input("Boshlang'ich pozitsiya (masalan 0, 1, 2, -1 ...): ").strip())
    step = int(input("O'suvchi qiymat / qadam (masalan +1, +2, -3, -4 ...): ").strip())

    skip_input = input(
        "Tashlab ketiladigan belgilar (Enter bossangiz standart '_{}' ishlatiladi): "
    ).strip()
    skip_chars = skip_input if skip_input else "_{}"

    natija = decrypt(ciphertext, start, step, skip_chars)

    print("\n--- NATIJA ---")
    print(natija)


if __name__ == "__main__":
    main()
