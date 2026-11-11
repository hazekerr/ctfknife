"""Базовый контракт плагина.

Каждый плагин — это подкласс :class:`Plugin`, который:

1. объявляет ``name`` (имя подкоманды CLI) и ``help`` (строка для ``--help``);
2. в :meth:`register` создаёт свой subparser и вешает на каждую конечную
   команду обработчик через ``set_defaults(handler=...)``.

Ядро ничего не знает о конкретных плагинах: оно находит их автоматически
(см. :mod:`core.loader`) и вызывает ``args.handler(args)``.
"""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from typing import Callable, ClassVar

#: Сигнатура обработчика команды. Возвращает код выхода процесса.
Handler = Callable[[argparse.Namespace], int]


class Plugin(ABC):
    """Абстрактный базовый класс для всех модулей инструмента."""

    #: Имя подкоманды верхнего уровня, например ``"forensics"``.
    name: ClassVar[str]
    #: Короткое описание для ``ctfknife --help``.
    help: ClassVar[str]
    #: Короткие синонимы подкоманды, например ``("fx",)``.
    aliases: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def register(self, subparsers: argparse._SubParsersAction) -> None:
        """Зарегистрировать подкоманды плагина в общем парсере.

        Args:
            subparsers: Объект, полученный из ``parser.add_subparsers()``.
        """

    # ---------------------------------------------------------------- helpers
    def make_parser(
        self, subparsers: argparse._SubParsersAction
    ) -> tuple[argparse.ArgumentParser, argparse._SubParsersAction]:
        """Создать parser плагина и вложенный набор его команд.

        Если пользователь вызвал плагин без команды, печатается его help.
        """
        parser = subparsers.add_parser(
            self.name,
            aliases=list(self.aliases),
            help=self.help,
            description=self.help,
        )
        parser.set_defaults(handler=lambda _a: (parser.print_help(), 1)[1])
        commands = parser.add_subparsers(title="commands", metavar="<command>")
        return parser, commands
