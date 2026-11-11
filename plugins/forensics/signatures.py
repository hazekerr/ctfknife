"""База сигнатур файлов («magic bytes»).

Источник сигнатур — общеизвестные спецификации форматов (аналог базы
``file``/``binwalk``, но компактная и читаемая). Чтобы добавить формат,
допишите строку в :data:`SIGNATURES`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signature:
    """Описание одного формата.

    Attributes:
        name: Человекочитаемое название формата.
        magic: Ожидаемые байты.
        offset: Смещение, на котором должны стоять ``magic``.
        extensions: Типичные расширения (без точки, в нижнем регистре).
        extra: Дополнительные проверки ``(offset, bytes)`` — например, для RIFF
            нужно отличить WAV от AVI и WEBP по байтам 8..11.
        embeddable: Искать ли сигнатуру внутри файла (carving). Отключено для
            коротких/шумных сигнатур, которые дают много ложных срабатываний.
    """

    name: str
    magic: bytes
    offset: int = 0
    extensions: tuple[str, ...] = ()
    extra: tuple[tuple[int, bytes], ...] = field(default_factory=tuple)
    embeddable: bool = True

    def matches(self, data: bytes, base: int = 0) -> bool:
        """Совпадает ли сигнатура, если файл начинается с позиции ``base``."""
        start = base + self.offset
        if data[start : start + len(self.magic)] != self.magic:
            return False
        return all(data[base + off : base + off + len(m)] == m for off, m in self.extra)


SIGNATURES: tuple[Signature, ...] = (
    # --- изображения
    Signature("PNG image", b"\x89PNG\r\n\x1a\n", extensions=("png",)),
    Signature("JPEG image", b"\xff\xd8\xff", extensions=("jpg", "jpeg", "jfif")),
    Signature("GIF image (87a)", b"GIF87a", extensions=("gif",)),
    Signature("GIF image (89a)", b"GIF89a", extensions=("gif",)),
    Signature("BMP image", b"BM", extensions=("bmp", "dib"), embeddable=False),
    Signature("TIFF image (LE)", b"II*\x00", extensions=("tif", "tiff")),
    Signature("TIFF image (BE)", b"MM\x00*", extensions=("tif", "tiff")),
    Signature("WEBP image", b"RIFF", extensions=("webp",), extra=((8, b"WEBP"),)),
    Signature("ICO icon", b"\x00\x00\x01\x00", extensions=("ico",), embeddable=False),
    Signature("Photoshop PSD", b"8BPS", extensions=("psd",)),
    # --- архивы и сжатие
    Signature("ZIP archive (also DOCX/XLSX/JAR/APK)", b"PK\x03\x04",
              extensions=("zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "epub")),
    Signature("ZIP archive (empty)", b"PK\x05\x06", extensions=("zip",), embeddable=False),
    Signature("RAR archive v1.5-4", b"Rar!\x1a\x07\x00", extensions=("rar",)),
    Signature("RAR archive v5", b"Rar!\x1a\x07\x01\x00", extensions=("rar",)),
    Signature("7-Zip archive", b"7z\xbc\xaf\x27\x1c", extensions=("7z",)),
    Signature("GZIP compressed", b"\x1f\x8b\x08", extensions=("gz", "tgz")),
    Signature("BZIP2 compressed", b"BZh", extensions=("bz2",), embeddable=False),
    Signature("XZ compressed", b"\xfd7zXZ\x00", extensions=("xz",)),
    Signature("Zstandard compressed", b"\x28\xb5\x2f\xfd", extensions=("zst",)),
    Signature("LZ4 frame", b"\x04\x22\x4d\x18", extensions=("lz4",)),
    Signature("TAR archive (ustar)", b"ustar", offset=257, extensions=("tar",)),
    Signature("Microsoft CAB", b"MSCF", extensions=("cab",)),
    # --- документы
    Signature("PDF document", b"%PDF-", extensions=("pdf",)),
    Signature("MS Office legacy (OLE2: DOC/XLS/PPT/MSI)", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
              extensions=("doc", "xls", "ppt", "msi", "msg")),
    Signature("Rich Text Format", b"{\\rtf", extensions=("rtf",)),
    Signature("SQLite 3 database", b"SQLite format 3\x00", extensions=("sqlite", "db", "sqlite3")),
    Signature("KeePass 2.x database", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", extensions=("kdbx",)),
    # --- исполняемые
    Signature("ELF executable", b"\x7fELF", extensions=("elf", "so", "o", "bin", "")),
    Signature("Windows PE / DOS MZ", b"MZ", extensions=("exe", "dll", "sys", "scr"), embeddable=False),
    Signature("Java class / Mach-O fat", b"\xca\xfe\xba\xbe", extensions=("class",)),
    Signature("Mach-O 64-bit (LE)", b"\xcf\xfa\xed\xfe", extensions=("macho", "dylib", "")),
    Signature("Python bytecode 3.x (approx.)", b"\r\n", offset=2, extensions=("pyc",), embeddable=False),
    Signature("WebAssembly binary", b"\x00asm", extensions=("wasm",)),
    Signature("Dalvik DEX", b"dex\n0", extensions=("dex",)),
    # --- аудио/видео
    Signature("WAV audio", b"RIFF", extensions=("wav",), extra=((8, b"WAVE"),)),
    Signature("AVI video", b"RIFF", extensions=("avi",), extra=((8, b"AVI "),)),
    Signature("MP3 audio (ID3 tag)", b"ID3", extensions=("mp3",)),
    Signature("FLAC audio", b"fLaC", extensions=("flac",)),
    Signature("OGG container", b"OggS", extensions=("ogg", "oga", "ogv", "opus")),
    Signature("MP4/MOV (ISO BMFF)", b"ftyp", offset=4, extensions=("mp4", "m4a", "mov", "3gp", "heic")),
    Signature("Matroska / WebM", b"\x1a\x45\xdf\xa3", extensions=("mkv", "webm")),
    Signature("MIDI audio", b"MThd", extensions=("mid", "midi")),
    # --- дампы сети и диски
    Signature("PCAP capture (LE)", b"\xd4\xc3\xb2\xa1", extensions=("pcap", "cap")),
    Signature("PCAP capture (BE)", b"\xa1\xb2\xc3\xd4", extensions=("pcap", "cap")),
    Signature("PCAPNG capture", b"\x0a\x0d\x0d\x0a", extensions=("pcapng",)),
    Signature("ISO 9660 image", b"CD001", offset=0x8001, extensions=("iso",)),
    Signature("Windows Event Log (EVTX)", b"ElfFile\x00", extensions=("evtx",)),
    Signature("Windows Registry hive", b"regf", extensions=("dat", "hiv")),
    # --- текст / ключи
    Signature("PEM block (key/cert)", b"-----BEGIN ", extensions=("pem", "key", "crt", "cer", "pub")),
    Signature("OpenSSH private key", b"-----BEGIN OPENSSH PRIVATE KEY-----", extensions=("key", "")),
    Signature("PGP armored", b"-----BEGIN PGP", extensions=("asc", "gpg", "pgp")),
    Signature("XML document", b"<?xml", extensions=("xml", "svg", "xhtml"), embeddable=False),
    Signature("Shell script (shebang)", b"#!", extensions=("sh", "py", "pl", "rb", ""), embeddable=False),
    Signature("UTF-8 BOM text", b"\xef\xbb\xbf", extensions=("txt", "csv"), embeddable=False),
)
