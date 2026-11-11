"""Общий слой вывода на ``rich``: консоль, сообщения, подсветка флагов, hexdump.

Все плагины печатают только через этот модуль, поэтому стиль вывода
одинаковый, а флаги ``--no-color`` / ``--flag-format`` работают везде.
"""

from __future__ import annotations

import os
import re

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

THEME = Theme(
    {
        "info": "cyan",
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "flag": "bold black on bright_green",
        "offset": "dim cyan",
        "muted": "dim",
    }
)

console = Console(theme=THEME, highlight=False)
err_console = Console(theme=THEME, stderr=True, highlight=False)

#: Шаблон флага по умолчанию: ``ctf{...}``, ``HTB{...}``, ``picoCTF{...}`` и т.п.
#: Переопределяется ``--flag-format`` или переменной окружения ``CTF_FLAG_REGEX``.
DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_\-]{2,24}\{[^{}\s]{1,200}\}"
_flag_re: re.Pattern[str] = re.compile(os.environ.get("CTF_FLAG_REGEX", DEFAULT_FLAG_REGEX))


def configure(*, no_color: bool = False, flag_regex: str | None = None) -> None:
    """Применить глобальные настройки вывода (вызывается из ``main.py``)."""
    global _flag_re
    if no_color:
        console.no_color = True
        err_console.no_color = True
    if flag_regex:
        _flag_re = re.compile(flag_regex)


def flag_pattern() -> re.Pattern[str]:
    """Текущий скомпилированный шаблон флага."""
    return _flag_re


def find_flags(text: str) -> list[str]:
    """Найти все подстроки, похожие на флаг."""
    return _flag_re.findall(text)


def highlight_flags(text: str, base_style: str = "") -> Text:
    """Вернуть ``rich.Text`` с подсвеченными флагами."""
    rich_text = Text(text, style=base_style)
    rich_text.highlight_regex(_flag_re, "flag")
    return rich_text


# ---------------------------------------------------------------- сообщения
def info(msg: str) -> None:
    console.print(f"[info][*][/info] {msg}")


def ok(msg: str) -> None:
    console.print(f"[ok][+][/ok] {msg}")


def warn(msg: str) -> None:
    err_console.print(f"[warn][!][/warn] {msg}")


def error(msg: str, title: str = "Error") -> None:
    err_console.print(Panel(msg, title=title, border_style="red", expand=False))


def announce_flags(text: str) -> None:
    """Если в тексте есть флаги — показать их отдельной заметной панелью."""
    flags = list(dict.fromkeys(find_flags(text)))
    if flags:
        body = Text("\n").join(Text(f, style="flag") for f in flags)
        console.print(Panel(body, title="🚩 Possible flag(s)", border_style="green", expand=False))


# ---------------------------------------------------------------- hexdump
def printable(data: bytes) -> str:
    """ASCII-представление байтов (непечатаемые → ``.``)."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)


def hexdump(data: bytes, base_offset: int = 0, width: int = 16, max_lines: int = 32) -> Text:
    """Классический hexdump ``offset | hex | ascii`` в виде ``rich.Text``."""
    out = Text(no_wrap=True, overflow="crop")
    lines = 0
    for i in range(0, len(data), width):
        if lines >= max_lines:
            out.append(f"... ({len(data) - i} more bytes)\n", style="muted")
            break
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        out.append(f"{base_offset + i:08x}  ", style="offset")
        out.append(hex_part)
        out.append("  │", style="muted")
        out.append(printable(chunk), style="green")
        out.append("│\n", style="muted")
        lines += 1
    out.rstrip()
    return out
