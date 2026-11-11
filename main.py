#!/usr/bin/env python3
"""CTF Swiss Army Knife — точка входа.

Ядро только собирает CLI из найденных плагинов и диспатчит команды.
Вся предметная логика живёт в ``plugins/<category>/``.

Примеры::

    python main.py crypto convert -f hex -t text 666c61677b686578217d
    python main.py crypto caesar "synt{pnrfne_vf_onpx}"
    python main.py forensics magic suspicious.jpg
    python main.py forensics strings dump.bin -n 6 --flags-only
    python main.py forensics lsb secret.png --auto
    python main.py web jwt eyJhbGciOi...
    python main.py web hashid 5f4dcc3b5aa765d61d8327deb882cf99
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Позволяет запускать `python main.py` из любой директории.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.table import Table  # noqa: E402

from core import ui  # noqa: E402
from core.io import InputError  # noqa: E402
from core.loader import LoadReport, discover  # noqa: E402

__version__ = "0.1.0"

BANNER = r"""[bold cyan]
   _____ _______ ______   _  __      _  __
  / ____|__   __|  ____| | |/ /     (_)/ _|
 | |       | |  | |__    | ' / _ __  _| |_ ___
 | |       | |  |  __|   |  < | '_ \| |  _/ _ \
 | |____   | |  | |      | . \| | | | | ||  __/
  \_____|  |_|  |_|      |_|\_\_| |_|_|_| \___|[/bold cyan]
 [dim]CTF Swiss Army Knife v{ver} — for CTF & education only[/dim]
"""


def build_parser(report: LoadReport) -> argparse.ArgumentParser:
    """Собрать корневой парсер и дать каждому плагину зарегистрироваться."""
    parser = argparse.ArgumentParser(
        prog="ctfknife",
        description="Modular CTF toolkit: crypto/encoding, forensics/stego, web/misc.",
        epilog="Data arguments accept: literal text | @path/to/file | - (stdin).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--no-color", action="store_true", help="disable colors")
    parser.add_argument("--debug", action="store_true", help="show full tracebacks")
    parser.add_argument(
        "--flag-format",
        metavar="REGEX",
        help=f"flag regex to highlight (default: {ui.DEFAULT_FLAG_REGEX!r}, env CTF_FLAG_REGEX)",
    )
    sub = parser.add_subparsers(title="modules", metavar="<module>")

    list_p = sub.add_parser("modules", help="list loaded modules")
    list_p.set_defaults(handler=lambda _a: show_modules(report))

    for plugin in report.plugins:
        plugin.register(sub)
    return parser


def show_modules(report: LoadReport) -> int:
    """Таблица загруженных (и сломанных) плагинов."""
    table = Table(title="Loaded modules", header_style="bold magenta")
    table.add_column("Module", style="cyan")
    table.add_column("Aliases")
    table.add_column("Description")
    for p in report.plugins:
        table.add_row(p.name, ", ".join(p.aliases), p.help)
    ui.console.print(table)
    for name, err in report.errors.items():
        ui.warn(f"Module [bold]{name}[/] failed to load: {err}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI. Возвращает код выхода."""
    report = discover("plugins")
    parser = build_parser(report)
    args = parser.parse_args(argv)
    ui.configure(no_color=args.no_color, flag_regex=args.flag_format)

    for name, err in report.errors.items():
        ui.warn(f"Module {name} skipped: {err}")

    handler = getattr(args, "handler", None)
    if handler is None:
        ui.console.print(BANNER.format(ver=__version__))
        parser.print_help()
        return 1

    try:
        return int(handler(args) or 0)
    except KeyboardInterrupt:
        ui.warn("Interrupted.")
        return 130
    except (InputError, ValueError, OSError, ImportError) as exc:
        if args.debug:
            ui.err_console.print_exception()
        else:
            ui.error(str(exc), title=type(exc).__name__)
        return 2
    except Exception:  # noqa: BLE001 — последний рубеж, всегда с трейсбеком
        ui.err_console.print_exception(show_locals=args.debug)
        return 3


if __name__ == "__main__":
    sys.exit(main())
