"""Классические шифры: Цезарь (с брутфорсом и частотным скорингом), ROT13, ROT47."""

from __future__ import annotations

import string
from dataclasses import dataclass

# Частоты букв английского языка, %.
ENGLISH_FREQ: dict[str, float] = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23, "g": 2.02,
    "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03, "m": 2.41, "n": 6.75,
    "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99, "s": 6.33, "t": 9.06, "u": 2.76,
    "v": 0.98, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07,
}


def caesar(text: str, shift: int) -> str:
    """Сдвинуть латинские буквы на ``shift`` позиций, сохраняя регистр."""
    k = shift % 26
    lower, upper = string.ascii_lowercase, string.ascii_uppercase
    table = str.maketrans(lower + upper, lower[k:] + lower[:k] + upper[k:] + upper[:k])
    return text.translate(table)


def rot13(text: str) -> str:
    return caesar(text, 13)


def rot47(text: str) -> str:
    """ROT47: сдвиг всех печатаемых ASCII ``!``..``~`` на 47."""
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def chi_squared(text: str) -> float:
    """Отклонение распределения букв от английского (меньше — «английнее»)."""
    letters = [c for c in text.lower() if c in ENGLISH_FREQ]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = {c: 0 for c in ENGLISH_FREQ}
    for c in letters:
        counts[c] += 1
    return sum((counts[c] - n * f / 100) ** 2 / (n * f / 100) for c, f in ENGLISH_FREQ.items())


@dataclass(frozen=True)
class CaesarCandidate:
    """Одна попытка брутфорса."""

    shift: int  # сдвиг, применённый для расшифровки (decrypt = caesar(text, shift))
    key: int  # ключ шифрования, которым текст был зашифрован
    plaintext: str
    chi2: float


def bruteforce(ciphertext: str) -> list[CaesarCandidate]:
    """Перебрать все 26 сдвигов; отсортировать по правдоподобию (chi²)."""
    out = []
    for shift in range(26):
        pt = caesar(ciphertext, shift)
        out.append(CaesarCandidate(shift, (26 - shift) % 26, pt, chi_squared(pt)))
    return sorted(out, key=lambda c: c.chi2)
