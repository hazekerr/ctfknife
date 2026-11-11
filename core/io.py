"""Унифицированное чтение входных данных.

Соглашение для всех команд, принимающих «данные»:

* ``"текст"``   — использовать как есть;
* ``@file.bin`` — прочитать содержимое файла;
* ``-``         — прочитать stdin (удобно для пайпов: ``cat x | ctfknife ...``).
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Защита от случайной загрузки гигантского файла целиком в память.
MAX_FILE_SIZE = 512 * 1024 * 1024  # 512 MiB


class InputError(Exception):
    """Ошибка чтения пользовательского ввода (понятное сообщение для CLI)."""


def read_file(path: str | Path, max_size: int = MAX_FILE_SIZE) -> bytes:
    """Прочитать файл в память с проверками существования и размера."""
    p = Path(path)
    if not p.is_file():
        raise InputError(f"File not found: {p}")
    size = p.stat().st_size
    if size > max_size:
        raise InputError(f"File is too large ({size} bytes > {max_size}).")
    return p.read_bytes()


def read_input(value: str) -> bytes:
    """Разобрать аргумент по соглашению ``текст`` / ``@файл`` / ``-``."""
    if value == "-":
        return sys.stdin.buffer.read()
    if value.startswith("@") and len(value) > 1:
        return read_file(value[1:])
    return value.encode("utf-8")


def read_text_input(value: str) -> str:
    """То же, что :func:`read_input`, но как строка без хвостовых переводов строки."""
    return read_input(value).decode("utf-8", errors="replace").strip("\r\n")
