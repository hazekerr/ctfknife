# CTF Knife — модульный CLI-инструмент для CTF

Набор утилит для задач категорий Crypto/Encoding и Forensics/Stego.
Предназначен для обучения и легального анализа данных на CTF-соревнованиях.

## Установка

Нужен Python 3.10+.

```bash
cd ctfknife
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py modules           # проверка: список загруженных модулей
```

Удобный алиас (Linux/macOS):

```bash
alias ctfknife="python $(pwd)/main.py"
```

## Структура проекта

```
ctfknife/
├── main.py               # ядро: загрузка плагинов, CLI, обработка ошибок
├── requirements.txt
├── core/
│   ├── plugin.py         # базовый класс Plugin
│   ├── loader.py         # автопоиск плагинов в plugins/
│   ├── ui.py             # вывод через rich, подсветка флагов, hexdump
│   └── io.py             # чтение ввода: текст | @файл | - (stdin)
└── plugins/
    ├── crypto/           # кодировки, Цезарь, ROT13/ROT47
    │   ├── encoding.py   # логика конвертации
    │   ├── classic.py    # классические шифры
    │   └── cli.py        # команды и вывод
    └── forensics/        # magic bytes, strings, LSB
        ├── signatures.py # база сигнатур файлов
        ├── analysis.py   # тип файла, энтропия, вложенные файлы, strings
        ├── lsb.py        # LSB-декодер
        └── cli.py        # команды и вывод
```

## Ввод данных

Аргумент с данными понимает три формы:

| Форма | Что значит |
|---|---|
| `"текст"` | использовать как есть |
| `@file.txt` | прочитать содержимое файла |
| `-` | прочитать stdin, например `cat x.txt \| python main.py crypto decode -` |

## Глобальные опции

| Опция | Описание |
|---|---|
| `--no-color` | отключить цвета |
| `--debug` | показывать полные трейсбеки |
| `--flag-format REGEX` | свой шаблон флага для подсветки, например `'HTB\{.*?\}'` |

Шаблон флага также задаётся переменной окружения `CTF_FLAG_REGEX`. Найденные флаги
подсвечиваются и выводятся отдельной панелью 🚩.

## Модуль crypto (алиас `c`)

Форматы: `text hex b64 b64url b32 b85 oct bin dec url`.

```bash
# Конвертация между форматами
python main.py crypto convert -f hex -t text 666c61677b686578217d
python main.py crypto convert -f text -t bin "flag" --sep " "

# Показать данные во всех форматах сразу
python main.py crypto encode "flag{test}"

# Авто-определение кодировки: пробует все форматы, сортирует по читаемости
python main.py crypto decode ZmxhZ3t0ZXN0fQ==

# Цезарь: перебор 26 сдвигов, лучший по частотному анализу (χ²) — первым
python main.py crypto caesar "synt{pnrfne_vf_onpx}"
python main.py crypto caesar "synt{...}" --shift 13

# ROT13 / ROT47
python main.py crypto rot13 "synt{grfg}"
python main.py crypto rot47 "7=28LE6DEN"
```

## Модуль forensics (алиас `fx`)

### magic — реальный тип файла

```bash
python main.py forensics magic suspicious.jpg
```

Показывает размер, MD5/SHA-256, энтропию, тип по сигнатуре, несовпадение
расширения (подсвечивается красным) и hexdump заголовка. Затем ищет сигнатуры
внутри файла (вложенные ZIP/PNG и т.п.) и подсказывает команду `dd` для вырезания.

| Опция | Описание |
|---|---|
| `--no-scan` | не искать вложенные файлы |
| `--head N` | сколько байт заголовка показать (по умолчанию 64) |

Энтропия ≥ 7.5 обычно означает сжатые или зашифрованные данные.

### strings — читаемые строки

```bash
python main.py fx strings dump.bin -n 6
python main.py fx strings dump.bin --grep password
python main.py fx strings dump.bin --flags-only
python main.py fx strings dump.bin --raw | sort -u > out.txt
```

| Опция | Описание |
|---|---|
| `-n N` | минимальная длина (по умолчанию 4) |
| `-e ascii\|utf16le\|all` | кодировка; UTF-16LE полезна для Windows-бинарей |
| `-g REGEX` | фильтр по регулярке (без учёта регистра) |
| `--flags-only` | только строки с флагом |
| `--limit N` | строк в таблице (0 — все) |
| `--raw` | простой вывод без таблицы, для пайпов |
| `-o FILE` | сохранить результат в файл |

### lsb — данные в младших битах PNG/BMP

```bash
# Перебор типовых комбинаций параметров, лучшие сверху
python main.py fx lsb secret.png --auto

# Ручное извлечение с выбранными параметрами
python main.py fx lsb secret.png -c RGB -b 0 --order row --bit-order msb -o out.bin
```

| Опция | Описание |
|---|---|
| `-c` | каналы и их порядок: `RGB`, `BGR`, `R`, `A`… |
| `-b` | битовые плоскости: `0`, `0,1`, `0-2` |
| `--order row\|col` | обход пикселей по строкам или столбцам |
| `--bit-order msb\|lsb` | упаковка битов в байт |
| `--max-bytes N` | остановиться после N байт |
| `--auto` / `--top N` | автоперебор и число строк в таблице |
| `-o FILE` | сохранить извлечённые байты |

Режим `--auto` оценивает каждый вариант по доле печатаемых символов, найденному
флагу и распознанной сигнатуре файла. Он подсказывает команду для полного
извлечения лучшего варианта. Если в результате распознан файл (например PNG или
ZIP), сохраните его через `-o` и проанализируйте `forensics magic`.

## Как добавить свой модуль

Загрузчик сам находит плагины в `plugins/`, `main.py` менять не нужно.

1. Создайте папку `plugins/<имя>/`.
2. Логику без `rich` и `argparse` вынесите в отдельный файл: её проще тестировать
   и импортировать в свои скрипты.
3. В `cli.py` опишите класс-наследник `Plugin`:

```python
import argparse
from core import ui
from core.io import read_text_input
from core.plugin import Plugin


class MyPlugin(Plugin):
    name = "mymod"
    aliases = ("mm",)
    help = "Короткое описание модуля"

    def register(self, subparsers: argparse._SubParsersAction) -> None:
        _, cmds = self.make_parser(subparsers)
        p = cmds.add_parser("hello", help="пример команды")
        p.add_argument("data", help="text | @file | -")
        p.set_defaults(handler=self.cmd_hello)

    def cmd_hello(self, args: argparse.Namespace) -> int:
        text = read_text_input(args.data)
        ui.ok(f"Получено {len(text)} символов")
        ui.announce_flags(text)
        return 0  # код выхода
```

4. Экспортируйте класс в `plugins/<имя>/__init__.py`:

```python
from .cli import MyPlugin
```

5. Проверьте: `python main.py modules`.

Если импорт плагина падает (например, нет зависимости), инструмент продолжит
работать без него и покажет предупреждение.

## Коды выхода

| Код | Значение |
|---|---|
| 0 | успех |
| 1 | нечего показать / вызов без команды |
| 2 | ошибка ввода (нет файла, неверный формат) |
| 3 | непредвиденная ошибка (трейсбек) |
| 130 | прервано Ctrl+C |
