"""CLI модуля Crypto & Encoding.

Команды::

    crypto convert DATA -f hex -t b64   — конвертация между форматами
    crypto encode  DATA                 — показать DATA во всех форматах
    crypto decode  DATA                 — авто-определение кодировки
    crypto caesar  TEXT [--shift N]     — брутфорс всех 26 сдвигов (chi²-скоринг)
    crypto rot13 / rot47 TEXT
"""

from __future__ import annotations

import argparse

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core import ui
from core.io import read_input, read_text_input
from core.plugin import Plugin

from . import classic, encoding


def _data_arg(p: argparse.ArgumentParser, name: str = "data") -> None:
    p.add_argument(name, help="text | @file | - (stdin)")


class CryptoPlugin(Plugin):
    """Crypto & Encoding."""

    name = "crypto"
    aliases = ("c",)
    help = "Crypto & Encoding: base64/hex/oct/bin/url converter, Caesar/ROT"

    def register(self, subparsers: argparse._SubParsersAction) -> None:
        _, cmds = self.make_parser(subparsers)
        fmts = encoding.FORMATS

        p = cmds.add_parser("convert", help="convert between encodings")
        _data_arg(p)
        p.add_argument("-f", "--from", dest="src", choices=fmts, required=True)
        p.add_argument("-t", "--to", dest="dst", choices=fmts, default="text")
        p.add_argument("--sep", default=" ", help="separator for oct/bin/dec output")
        p.set_defaults(handler=self.cmd_convert)

        p = cmds.add_parser("encode", help="show data in every encoding")
        _data_arg(p)
        p.add_argument("-f", "--from", dest="src", choices=fmts, default="text")
        p.set_defaults(handler=self.cmd_encode)

        p = cmds.add_parser("decode", help="auto-detect encoding and decode")
        _data_arg(p)
        p.set_defaults(handler=self.cmd_decode)

        p = cmds.add_parser("caesar", help="Caesar cipher: brute-force or fixed shift")
        _data_arg(p, "text")
        p.add_argument("-s", "--shift", type=int, help="apply this shift only")
        p.add_argument("--top", type=int, default=26, help="rows to show (default all 26)")
        p.set_defaults(handler=self.cmd_caesar)

        for rot in ("rot13", "rot47"):
            p = cmds.add_parser(rot, help=f"{rot.upper()} transform")
            _data_arg(p, "text")
            p.set_defaults(handler=self.cmd_rot, rot=rot)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _load(value: str, src: str) -> bytes:
        return read_input(value) if src == "text" else encoding.decode(read_text_input(value), src)

    # ---------------------------------------------------------------- commands
    def cmd_convert(self, args: argparse.Namespace) -> int:
        raw = self._load(args.data, args.src)
        result = encoding.encode(raw, args.dst, sep=args.sep)
        ui.console.print(Panel(ui.highlight_flags(result), title=f"{args.src} → {args.dst}",
                               subtitle=f"{len(raw)} bytes", border_style="cyan"))
        ui.announce_flags(result)
        return 0

    def cmd_encode(self, args: argparse.Namespace) -> int:
        raw = self._load(args.data, args.src)
        table = Table(title=f"{len(raw)} bytes in all encodings", box=box.ROUNDED, header_style="bold magenta")
        table.add_column("Format", style="cyan", no_wrap=True)
        table.add_column("Value", overflow="fold")
        for fmt in encoding.FORMATS:
            table.add_row(fmt, encoding.encode(raw, fmt))
        ui.console.print(table)
        return 0

    def cmd_decode(self, args: argparse.Namespace) -> int:
        text = read_text_input(args.data)
        results = encoding.auto_decode(text)
        if not results:
            ui.warn("No known encoding matched.")
            return 1
        table = Table(title="Auto-decode candidates", box=box.ROUNDED, header_style="bold magenta")
        table.add_column("Format", style="cyan", no_wrap=True)
        table.add_column("Printable", justify="right")
        table.add_column("Result", overflow="fold")
        for r in results:
            style = "ok" if r.printable > 0.95 else ("warn" if r.printable > 0.7 else "muted")
            shown = encoding.encode(r.data, "text") if r.printable > 0.7 else r.data.hex()
            table.add_row(r.fmt, Text(f"{r.printable:.0%}", style=style), ui.highlight_flags(shown))
        ui.console.print(table)
        ui.announce_flags(encoding.encode(results[0].data, "text"))
        return 0

    def cmd_caesar(self, args: argparse.Namespace) -> int:
        text = read_text_input(args.text)
        if args.shift is not None:
            result = classic.caesar(text, args.shift)
            ui.console.print(Panel(ui.highlight_flags(result), title=f"Caesar shift {args.shift}"))
            ui.announce_flags(result)
            return 0

        candidates = classic.bruteforce(text)
        table = Table(title="Caesar brute-force (most English-like first)", box=box.ROUNDED,
                      header_style="bold magenta")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Shift", justify="right", style="cyan")
        table.add_column("Key", justify="right", style="dim")
        table.add_column("χ²", justify="right")
        table.add_column("Plaintext", overflow="fold")
        for i, c in enumerate(candidates[: args.top], 1):
            # Шаблон флага `xxx{...}` переживает любой сдвиг, поэтому
            # подсвечиваем только самый правдоподобный вариант.
            plain = ui.highlight_flags(c.plaintext, "bold") if i == 1 else Text(c.plaintext)
            mark = " [dim](ROT13)[/dim]" if c.shift == 13 else ""
            table.add_row(str(i), f"+{c.shift}{mark}", str(c.key), f"{c.chi2:.1f}", plain)
        ui.console.print(table)
        ui.announce_flags(candidates[0].plaintext)
        return 0

    def cmd_rot(self, args: argparse.Namespace) -> int:
        text = read_text_input(args.text)
        result = classic.rot13(text) if args.rot == "rot13" else classic.rot47(text)
        ui.console.print(Panel(ui.highlight_flags(result), title=args.rot.upper(), border_style="cyan"))
        ui.announce_flags(result)
        return 0
