"""Кодировки: text / hex / base64 / base32 / base85 / oct / bin / dec / url.

Основная идея — всё конвертируется через ``bytes``:
``decode(строка, формат) -> bytes -> encode(bytes, формат) -> строка``.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass

FORMATS: tuple[str, ...] = ("text", "hex", "b64", "b64url", "b32", "b85", "oct", "bin", "dec", "url")

_SPLIT = re.compile(r"[\s,;:]+")


def _pad(s: str, block: int) -> str:
    return s + "=" * (-len(s) % block)


def _tokens(s: str, chunk: int) -> list[str]:
    """Разбить строку чисел по разделителям, либо на чанки фиксированной длины."""
    parts = [p for p in _SPLIT.split(s.strip()) if p]
    if len(parts) == 1 and chunk and len(parts[0]) > chunk:
        one = parts[0]
        if len(one) % chunk:
            raise ValueError(f"length {len(one)} is not a multiple of {chunk}")
        return [one[i : i + chunk] for i in range(0, len(one), chunk)]
    return parts


def _ints_to_bytes(tokens: list[str], base: int) -> bytes:
    values = [int(t, base) for t in tokens]
    if any(not 0 <= v <= 255 for v in values):
        raise ValueError("value out of byte range 0..255")
    return bytes(values)


def decode(data: str, fmt: str) -> bytes:
    """Декодировать строку из формата ``fmt`` в байты.

    Raises:
        ValueError: если данные не соответствуют формату.
    """
    s = data.strip()
    try:
        match fmt:
            case "text":
                return data.encode("utf-8")
            case "hex":
                cleaned = re.sub(r"0x|\\x|[\s:,]", "", s, flags=re.IGNORECASE)
                return bytes.fromhex(cleaned)
            case "b64":
                return base64.b64decode(_pad(re.sub(r"\s", "", s), 4), validate=True)
            case "b64url":
                return base64.urlsafe_b64decode(_pad(re.sub(r"\s", "", s), 4))
            case "b32":
                return base64.b32decode(_pad(re.sub(r"\s", "", s).upper(), 8))
            case "b85":
                return base64.b85decode(s)
            case "oct":
                return _ints_to_bytes(_tokens(s, 3), 8)
            case "bin":
                return _ints_to_bytes(_tokens(s, 8), 2)
            case "dec":
                return _ints_to_bytes(_tokens(s, 0), 10)
            case "url":
                return urllib.parse.unquote_to_bytes(s.replace("+", " "))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"not valid {fmt}: {exc}") from None
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


def encode(data: bytes, fmt: str, sep: str = " ") -> str:
    """Закодировать байты в формат ``fmt``.

    Args:
        sep: Разделитель для поэлементных форматов (hex/oct/bin/dec).
            Для hex по умолчанию разделитель не используется.
    """
    match fmt:
        case "text":
            return data.decode("utf-8", errors="backslashreplace")
        case "hex":
            return data.hex()
        case "b64":
            return base64.b64encode(data).decode()
        case "b64url":
            return base64.urlsafe_b64encode(data).decode().rstrip("=")
        case "b32":
            return base64.b32encode(data).decode()
        case "b85":
            return base64.b85encode(data).decode()
        case "oct":
            return sep.join(f"{b:03o}" for b in data)
        case "bin":
            return sep.join(f"{b:08b}" for b in data)
        case "dec":
            return sep.join(str(b) for b in data)
        case "url":
            return urllib.parse.quote_from_bytes(data, safe="")
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


@dataclass(frozen=True)
class AutoResult:
    """Удачная попытка декодирования в режиме авто-определения."""

    fmt: str
    data: bytes
    printable: float


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13)) / len(data)


def auto_decode(data: str) -> list[AutoResult]:
    """Попробовать все форматы и вернуть удачные, самые «читаемые» первыми."""
    results: list[AutoResult] = []
    for fmt in FORMATS:
        if fmt == "text":
            continue
        try:
            out = decode(data, fmt)
        except ValueError:
            continue
        if not out or (fmt == "url" and out == data.strip().encode()):
            continue  # url-decode без изменений ничего не говорит
        results.append(AutoResult(fmt, out, printable_ratio(out)))
    return sorted(results, key=lambda r: r.printable, reverse=True)
