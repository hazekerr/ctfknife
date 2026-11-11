"""LSB-стеганография: извлечение данных из младших битов пикселей PNG/BMP.

Типовые параметры CTF-задач (в духе zsteg / StegSolve «Data Extract»):

* каналы: ``R``, ``G``, ``B``, ``A`` в любом порядке (``RGB``, ``BGR``, ``A``…);
* битовые плоскости: ``0`` (LSB), иногда ``0,1`` или ``1``;
* обход: по строкам (``row``) или по столбцам (``col``);
* упаковка битов в байт: ``msb`` (первый бит — старший) или ``lsb``.

Pillow импортируется лениво, чтобы остальные команды работали и без него.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from .analysis import identify

CHANNEL_INDEX = {"R": 0, "G": 1, "B": 2, "A": 3}


@dataclass(frozen=True)
class LSBParams:
    """Набор параметров одной попытки извлечения."""

    channels: str = "RGB"
    bits: tuple[int, ...] = (0,)
    order: str = "row"  # row | col
    bit_order: str = "msb"  # msb | lsb

    def label(self) -> str:
        bits = ",".join(map(str, self.bits))
        return f"{self.channels} b{bits} {self.order} {self.bit_order}"


@dataclass
class Image:
    """Минимальное представление картинки: размер + пиксели RGBA."""

    width: int
    height: int
    pixels: Sequence[tuple[int, int, int, int]]
    original_mode: str


def load_image(path: str | Path) -> Image:
    """Открыть изображение и привести к RGBA."""
    try:
        from PIL import Image as PILImage
    except ImportError as exc:  # pragma: no cover — зависит от окружения
        raise ImportError("LSB requires Pillow: pip install pillow") from exc

    with PILImage.open(path) as img:
        mode = img.mode
        rgba = img.convert("RGBA")
        data = rgba.get_flattened_data() if hasattr(rgba, "get_flattened_data") else rgba.getdata()
        return Image(rgba.width, rgba.height, list(data), mode)


def parse_bits(spec: str) -> tuple[int, ...]:
    """``"0"`` → (0,), ``"0,1"`` → (0, 1), ``"0-2"`` → (0, 1, 2)."""
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            out.extend(range(lo, hi + 1))
        elif part:
            out.append(int(part))
    if not out or any(not 0 <= b <= 7 for b in out):
        raise ValueError(f"Invalid bit planes {spec!r}: expected values 0..7")
    return tuple(out)


def _pixel_order(width: int, height: int, order: str) -> Iterable[int]:
    if order == "row":
        return range(width * height)
    if order == "col":
        return (y * width + x for x in range(width) for y in range(height))
    raise ValueError(f"Unknown order {order!r} (use row|col)")


def _bit_stream(img: Image, p: LSBParams) -> Iterator[int]:
    try:
        idx = [CHANNEL_INDEX[c] for c in p.channels.upper()]
    except KeyError as exc:
        raise ValueError(f"Unknown channel {exc.args[0]!r} (use R, G, B, A)") from None
    px = img.pixels
    for i in _pixel_order(img.width, img.height, p.order):
        pixel = px[i]
        for c in idx:
            value = pixel[c]
            for b in p.bits:
                yield (value >> b) & 1


def extract(img: Image, p: LSBParams, max_bytes: int | None = None) -> bytes:
    """Извлечь байты из выбранных битовых плоскостей.

    Args:
        img: Изображение из :func:`load_image`.
        p: Параметры извлечения.
        max_bytes: Остановиться после N байт (быстрый предпросмотр).
    """
    if p.bit_order not in ("msb", "lsb"):
        raise ValueError("bit_order must be msb or lsb")
    out = bytearray()
    acc = n = 0
    msb = p.bit_order == "msb"
    for bit in _bit_stream(img, p):
        if msb:
            acc = (acc << 1) | bit
        else:
            acc |= bit << n
        n += 1
        if n == 8:
            out.append(acc)
            acc = n = 0
            if max_bytes is not None and len(out) >= max_bytes:
                break
    return bytes(out)


# ----------------------------------------------------------------- auto mode
@dataclass(frozen=True)
class Candidate:
    """Результат одной попытки в режиме ``--auto``."""

    params: LSBParams
    score: float
    printable_ratio: float
    magic: str | None
    preview: bytes


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return good / len(data)


AUTO_CHANNELS = ("RGB", "BGR", "R", "G", "B", "A", "RGBA")
AUTO_BITS = ((0,), (1,), (0, 1))


def auto_candidates() -> list[LSBParams]:
    """Типовые комбинации параметров, которые стоит перебрать в первую очередь."""
    return [
        LSBParams(ch, bits, order, bo)
        for ch, bits, order, bo in itertools.product(AUTO_CHANNELS, AUTO_BITS, ("row", "col"), ("msb", "lsb"))
    ]


def auto_scan(
    img: Image,
    flag_finder: Callable[[str], list[str]],
    sample_bytes: int = 1024,
    progress: Callable[[LSBParams], None] | None = None,
) -> list[Candidate]:
    """Перебрать типовые комбинации и отсортировать по «осмысленности».

    Оценка: доля печатаемых символов + бонус за найденный флаг и за
    распознанную сигнатуру файла (часто в LSB спрятан целый PNG/ZIP).
    """
    has_alpha_data = any(p[3] != 255 for p in img.pixels[:4096])
    results: list[Candidate] = []
    for params in auto_candidates():
        if "A" in params.channels and not has_alpha_data:
            if progress:
                progress(params)
            continue
        data = extract(img, params, max_bytes=sample_bytes)
        ratio = printable_ratio(data)
        sigs = identify(data)
        magic = sigs[0].name if sigs and len(sigs[0].magic) >= 3 else None
        flags = flag_finder(data.decode("latin-1"))
        score = ratio + (2.0 if flags else 0.0) + (1.0 if magic else 0.0)
        results.append(Candidate(params, round(score, 3), ratio, magic, data[:64]))
        if progress:
            progress(params)
    return sorted(results, key=lambda c: c.score, reverse=True)
