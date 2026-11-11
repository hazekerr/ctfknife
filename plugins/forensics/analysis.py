"""Чистая логика форензики: определение типа, энтропия, carving, strings.

Модуль не зависит от ``rich``/``argparse`` — его можно импортировать
в свои скрипты-решалки: ``from plugins.forensics.analysis import identify``.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .signatures import SIGNATURES, Signature


# ======================================================================
# Magic bytes
# ======================================================================
def identify(data: bytes) -> list[Signature]:
    """Определить формат по сигнатурам в начале данных.

    Returns:
        Совпавшие сигнатуры, самые специфичные (длинные) первыми.
    """
    hits = [s for s in SIGNATURES if s.matches(data)]
    return sorted(hits, key=lambda s: len(s.magic) + sum(len(m) for _, m in s.extra), reverse=True)


@dataclass(frozen=True)
class ExtensionVerdict:
    """Результат сравнения расширения файла с реальным содержимым."""

    extension: str
    detected: Signature | None
    mismatch: bool
    expected_extensions: tuple[str, ...]


def check_extension(path: str | Path, matches: list[Signature]) -> ExtensionVerdict:
    """Сравнить расширение файла с тем, что показали magic bytes."""
    ext = Path(path).suffix.lower().lstrip(".")
    if not matches:
        return ExtensionVerdict(ext, None, False, ())
    expected = tuple(dict.fromkeys(e for s in matches for e in s.extensions))
    mismatch = ext not in expected
    return ExtensionVerdict(ext, matches[0], mismatch, expected)


def shannon_entropy(data: bytes) -> float:
    """Энтропия Шеннона в битах на байт (0.0 … 8.0).

    ~7.9+ — сжатые/зашифрованные данные; < 5 — обычно текст или код.
    """
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def describe_entropy(value: float) -> str:
    """Человекочитаемая интерпретация энтропии."""
    if value >= 7.5:
        return "very high — compressed or encrypted"
    if value >= 6.0:
        return "high — binary / packed data"
    if value >= 4.0:
        return "medium — text, code or structured binary"
    return "low — sparse / repetitive data"


# ======================================================================
# Carving: поиск файлов, спрятанных внутри других (binwalk-lite)
# ======================================================================
@dataclass(frozen=True)
class EmbeddedHit:
    """Сигнатура, найденная не в начале файла."""

    offset: int
    signature: Signature


def scan_embedded(
    data: bytes,
    progress: Callable[[Signature], None] | None = None,
    limit_per_sig: int = 50,
) -> list[EmbeddedHit]:
    """Найти сигнатуры известных форматов внутри данных (offset > 0).

    Args:
        data: Содержимое файла.
        progress: Колбэк, вызывается после проверки каждой сигнатуры
            (используется для прогресс-бара в CLI).
        limit_per_sig: Максимум находок одной сигнатуры (защита от шума).
    """
    hits: list[EmbeddedHit] = []
    seen: set[tuple[int, str]] = set()
    for sig in SIGNATURES:
        if sig.embeddable:
            found = 0
            pos = data.find(sig.magic, 1)
            while pos != -1 and found < limit_per_sig:
                base = pos - sig.offset
                if base > 0 and sig.matches(data, base) and (base, sig.name) not in seen:
                    seen.add((base, sig.name))
                    hits.append(EmbeddedHit(base, sig))
                    found += 1
                pos = data.find(sig.magic, pos + 1)
        if progress:
            progress(sig)
    return sorted(hits, key=lambda h: h.offset)


# ======================================================================
# strings
# ======================================================================
@dataclass(frozen=True)
class FoundString:
    """Читаемая строка, найденная в бинарных данных."""

    offset: int
    encoding: str
    value: str


_PRINTABLE = rb"[\x20-\x7e\t]"


def _ascii_re(min_len: int) -> re.Pattern[bytes]:
    return re.compile(_PRINTABLE + rb"{%d,}" % min_len)


def _utf16le_re(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"(?:" + _PRINTABLE + rb"\x00){%d,}" % min_len)


def extract_strings(
    data: bytes,
    min_len: int = 4,
    encodings: tuple[str, ...] = ("ascii",),
) -> Iterator[FoundString]:
    """Аналог ``strings -n N`` (+ ``-e l`` для UTF-16LE, как в Windows-бинарях).

    Args:
        data: Бинарные данные.
        min_len: Минимальная длина строки в символах.
        encodings: Любая комбинация ``"ascii"`` и ``"utf16le"``.

    Yields:
        :class:`FoundString` в порядке возрастания смещения.
    """
    if min_len < 1:
        raise ValueError("min_len must be >= 1")
    results: list[FoundString] = []
    if "ascii" in encodings:
        for m in _ascii_re(min_len).finditer(data):
            results.append(FoundString(m.start(), "ascii", m.group().decode("ascii")))
    if "utf16le" in encodings:
        for m in _utf16le_re(min_len).finditer(data):
            results.append(FoundString(m.start(), "utf16le", m.group().decode("utf-16-le")))
    yield from sorted(results, key=lambda s: s.offset)
