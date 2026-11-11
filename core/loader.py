"""Автоматическое обнаружение плагинов.

Плагином считается любой пакет/модуль внутри ``plugins/``, в котором
объявлен подкласс :class:`core.plugin.Plugin`. Чтобы добавить новую
категорию (например ``pwn`` или ``osint``), достаточно положить папку
``plugins/pwn/`` — правка ``main.py`` не нужна.

Падение импорта одного плагина (например, не установлена зависимость)
не валит весь инструмент: плагин пропускается с предупреждением.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from types import ModuleType

from core.plugin import Plugin


@dataclass
class LoadReport:
    """Результат загрузки: успешно подгруженные плагины и ошибки."""

    plugins: list[Plugin] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def _plugin_classes(module: ModuleType) -> list[type[Plugin]]:
    """Вернуть все конкретные подклассы Plugin, объявленные в модуле."""
    return [
        obj
        for _, obj in inspect.getmembers(module, inspect.isclass)
        if issubclass(obj, Plugin)
        and obj is not Plugin
        and not inspect.isabstract(obj)
        and obj.__module__.startswith(module.__name__)
    ]


def discover(package: str = "plugins") -> LoadReport:
    """Импортировать все модули пакета ``package`` и собрать плагины.

    Args:
        package: Имя пакета с плагинами.

    Returns:
        :class:`LoadReport` с экземплярами плагинов, отсортированными по имени.
    """
    report = LoadReport()
    pkg = importlib.import_module(package)
    for info in pkgutil.iter_modules(pkg.__path__, prefix=f"{package}."):
        if info.name.rsplit(".", 1)[-1].startswith("_"):
            continue
        try:
            module = importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001 — изолируем сломанный плагин
            report.errors[info.name] = f"{type(exc).__name__}: {exc}"
            continue
        report.plugins.extend(cls() for cls in _plugin_classes(module))
    report.plugins.sort(key=lambda p: p.name)
    return report
