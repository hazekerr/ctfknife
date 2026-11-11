"""CLI-обвязка модуля Forensics & Stego (argparse + rich).

Команды::

    forensics magic   FILE   — реальный тип файла, энтропия, хэши, вложенные файлы
    forensics strings FILE   — читаемые строки (ASCII / UTF-16LE), grep, флаги
    forensics lsb     IMAGE  — LSB-декодер для PNG/BMP (ручной режим и --auto)
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from core import ui
from core.io import read_file
from core.plugin import Plugin

from . import analysis, lsb


def _progress() -> Progress:
    """Единый стиль прогресс-бара для модуля."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=ui.console,
        transient=True,
    )


class ForensicsPlugin(Plugin):
    """Forensics & Stego: magic bytes, strings, LSB."""

    name = "forensics"
    aliases = ("fx",)
    help = "Forensics & Stego: magic bytes, strings, LSB decoder"

    # ================================================================ argparse
    def register(self, subparsers: argparse._SubParsersAction) -> None:
        _, cmds = self.make_parser(subparsers)

        p = cmds.add_parser("magic", help="detect real file type by magic bytes, find embedded files")
        p.add_argument("file", type=Path)
        p.add_argument("--no-scan", action="store_true", help="skip embedded-file scan")
        p.add_argument("--head", type=int, default=64, metavar="N", help="hexdump first N bytes (default 64)")
        p.set_defaults(handler=self.cmd_magic)

        p = cmds.add_parser("strings", help="extract printable strings (like `strings`)")
        p.add_argument("file", type=Path)
        p.add_argument("-n", "--min-len", type=int, default=4, help="minimum length (default 4)")
        p.add_argument("-e", "--encoding", choices=("ascii", "utf16le", "all"), default="all")
        p.add_argument("-g", "--grep", metavar="REGEX", help="keep only strings matching REGEX (case-insensitive)")
        p.add_argument("--flags-only", action="store_true", help="keep only strings containing a flag")
        p.add_argument("--limit", type=int, default=300, help="max rows in table (default 300, 0 = all)")
        p.add_argument("--raw", action="store_true", help="plain output for piping (no table)")
        p.add_argument("-o", "--out", type=Path, help="save all matched strings to file")
        p.set_defaults(handler=self.cmd_strings)

        p = cmds.add_parser("lsb", help="extract LSB-hidden data from PNG/BMP")
        p.add_argument("image", type=Path)
        p.add_argument("-c", "--channels", default="RGB", help="channel order, e.g. RGB, BGR, R, A (default RGB)")
        p.add_argument("-b", "--bits", default="0", help="bit planes: 0 | 0,1 | 0-2 (default 0 = LSB)")
        p.add_argument("--order", choices=("row", "col"), default="row", help="pixel traversal (default row)")
        p.add_argument("--bit-order", choices=("msb", "lsb"), default="msb", help="bit packing (default msb)")
        p.add_argument("--max-bytes", type=int, default=None, help="stop after N extracted bytes")
        p.add_argument("--auto", action="store_true", help="brute-force common parameter combos")
        p.add_argument("--top", type=int, default=10, help="rows to show in --auto mode (default 10)")
        p.add_argument("-o", "--out", type=Path, help="write extracted bytes to file")
        p.set_defaults(handler=self.cmd_lsb)

    # ================================================================ magic
    def cmd_magic(self, args: argparse.Namespace) -> int:
        data = read_file(args.file)
        matches = analysis.identify(data)
        verdict = analysis.check_extension(args.file, matches)
        entropy = analysis.shannon_entropy(data)

        info = Table.grid(padding=(0, 2))
        info.add_column(style="bold cyan", justify="right")
        info.add_column()
        info.add_row("File", str(args.file))
        info.add_row("Size", f"{len(data):,} bytes")
        info.add_row("MD5", hashlib.md5(data).hexdigest())
        info.add_row("SHA-256", hashlib.sha256(data).hexdigest())
        info.add_row("Entropy", f"{entropy:.4f} bits/byte  [dim]({analysis.describe_entropy(entropy)})[/dim]")

        if verdict.detected is None:
            info.add_row("Detected", "[warn]unknown — no known signature at offset 0[/warn]")
        else:
            info.add_row("Detected", f"[ok]{verdict.detected.name}[/ok]")
            for other in matches[1:]:
                info.add_row("", f"[dim]also matches: {other.name}[/dim]")
            ext_shown = f".{verdict.extension}" if verdict.extension else "(none)"
            if verdict.mismatch:
                expected = ", ".join(f".{e}" for e in verdict.expected_extensions if e) or "(none)"
                info.add_row(
                    "Extension",
                    f"[err]MISMATCH[/err] {ext_shown} → expected {expected}",
                )
            else:
                info.add_row("Extension", f"[ok]OK[/ok] {ext_shown}")

        border = "red" if verdict.mismatch else "cyan"
        ui.console.print(Panel(info, title="🔎 Magic bytes analysis", border_style=border, expand=False))
        ui.console.print(Panel(ui.hexdump(data[: args.head]), title=f"Header ({min(args.head, len(data))} bytes)",
                               border_style="dim", expand=False))

        if not args.no_scan:
            self._embedded_report(args.file, data)
        return 0

    def _embedded_report(self, path: Path, data: bytes) -> None:
        with _progress() as progress:
            task = progress.add_task("Scanning for embedded files", total=len(analysis.SIGNATURES))
            hits = analysis.scan_embedded(data, progress=lambda _s: progress.advance(task))

        if not hits:
            ui.ok("No embedded signatures found.")
            return
        table = Table(title="📦 Embedded signatures (carving candidates)", box=box.ROUNDED, header_style="bold magenta")
        table.add_column("Offset (hex)", style="offset", justify="right")
        table.add_column("Offset (dec)", justify="right")
        table.add_column("Type", style="yellow")
        for hit in hits:
            table.add_row(f"0x{hit.offset:08x}", str(hit.offset), hit.signature.name)
        ui.console.print(table)
        first = hits[0].offset
        cmd = f"dd if={shlex.quote(str(path))} of=carved_{first:x}.bin bs=1 skip={first}"
        ui.info(f"Carve the first one with: [bold]{cmd}[/bold]  (or binwalk -e / foremost)")

    # ================================================================ strings
    def cmd_strings(self, args: argparse.Namespace) -> int:
        data = read_file(args.file)
        encodings = ("ascii", "utf16le") if args.encoding == "all" else (args.encoding,)
        grep = re.compile(args.grep, re.IGNORECASE) if args.grep else None

        with ui.console.status(f"Extracting strings from {args.file} ...", spinner="dots"):
            found = list(analysis.extract_strings(data, args.min_len, encodings))
        if grep:
            found = [s for s in found if grep.search(s.value)]
        if args.flags_only:
            found = [s for s in found if ui.find_flags(s.value)]

        if args.out:
            args.out.write_text("\n".join(s.value for s in found), encoding="utf-8")
            ui.ok(f"Saved {len(found)} strings to {args.out}")

        if args.raw:
            for s in found:
                ui.console.print(s.value, markup=False, highlight=False, soft_wrap=True)
            return 0

        shown = found if args.limit == 0 else found[: args.limit]
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold magenta", show_lines=False)
        table.add_column("Offset", style="offset", justify="right", no_wrap=True)
        table.add_column("Enc", style="dim", no_wrap=True)
        table.add_column("String", overflow="fold")
        for s in shown:
            text = ui.highlight_flags(s.value)
            if grep:
                text.highlight_regex(grep, "bold yellow")
            table.add_row(f"0x{s.offset:08x}", "u16" if s.encoding == "utf16le" else "asc", text)
        ui.console.print(table)

        summary = f"{len(found)} string(s) found (min length {args.min_len}, {'+'.join(encodings)})"
        if len(shown) < len(found):
            summary += f"; showing first {len(shown)} — use --limit 0, --raw or -o"
        ui.info(summary)
        ui.announce_flags("\n".join(s.value for s in found))
        return 0

    # ================================================================ lsb
    def cmd_lsb(self, args: argparse.Namespace) -> int:
        if not args.image.is_file():
            raise FileNotFoundError(f"Image not found: {args.image}")
        with ui.console.status("Loading image ...", spinner="dots"):
            img = lsb.load_image(args.image)
        ui.info(f"{args.image}: {img.width}x{img.height}, mode {img.original_mode} "
                f"(capacity at 1 bit/RGB channel ≈ {img.width * img.height * 3 // 8:,} bytes)")
        if img.original_mode == "P":
            ui.warn("Palette image: values are taken after palette→RGBA conversion.")

        if args.auto:
            return self._lsb_auto(img, args.top)

        params = lsb.LSBParams(args.channels.upper(), lsb.parse_bits(args.bits), args.order, args.bit_order)
        with ui.console.status(f"Extracting [{params.label()}] ...", spinner="dots"):
            data = lsb.extract(img, params, max_bytes=args.max_bytes)
        self._show_payload(data, params)
        if args.out:
            args.out.write_bytes(data)
            ui.ok(f"Wrote {len(data):,} bytes to {args.out}")
        return 0

    def _lsb_auto(self, img: lsb.Image, top: int) -> int:
        candidates = lsb.auto_candidates()
        with _progress() as progress:
            task = progress.add_task("Trying LSB combinations", total=len(candidates))
            results = lsb.auto_scan(img, ui.find_flags, progress=lambda _p: progress.advance(task))

        table = Table(title="🧪 LSB auto-scan (best first)", box=box.ROUNDED, header_style="bold magenta")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Params", style="cyan", no_wrap=True)
        table.add_column("Score", justify="right")
        table.add_column("Printable", justify="right")
        table.add_column("Magic", style="yellow")
        table.add_column("Preview", overflow="fold")
        for i, c in enumerate(results[:top], 1):
            score_style = "ok" if c.score >= 1.5 else ("warn" if c.score >= 0.8 else "muted")
            table.add_row(
                str(i), c.params.label(), Text(f"{c.score:.2f}", style=score_style),
                f"{c.printable_ratio:.0%}", c.magic or "", ui.highlight_flags(ui.printable(c.preview)),
            )
        ui.console.print(table)
        if results:
            best = results[0].params
            ui.info(
                "Extract the best one fully: [bold]lsb IMAGE "
                f"-c {best.channels} -b {','.join(map(str, best.bits))} --order {best.order} "
                f"--bit-order {best.bit_order} -o out.bin[/bold]"
            )
            ui.announce_flags("\n".join(ui.printable(c.preview) for c in results[:top]))
        return 0

    def _show_payload(self, data: bytes, params: lsb.LSBParams) -> None:
        sigs = analysis.identify(data)
        kind = f"[ok]{sigs[0].name}[/ok]" if sigs else "[dim]no known signature[/dim]"
        ui.console.print(Panel(
            ui.hexdump(data[:256], max_lines=16),
            title=f"LSB [{params.label()}] — {len(data):,} bytes — {kind}",
            border_style="cyan", expand=False,
        ))
        text = data.decode("latin-1")
        head = text[:1000]
        if lsb.printable_ratio(data[:1000]) > 0.7:
            ui.console.print(Panel(ui.highlight_flags(head), title="As text (first 1000 chars)", expand=False))
        ui.announce_flags(text)
