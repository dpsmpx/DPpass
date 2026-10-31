#!/usr/bin/env python3
"""Сравнение двух сборок APK по записям zip — для воспроизводимости (этап 5, работа 8).

    python3 tools/release/compare_apks.py A.apk B.apk

Сначала — суммы SHA-256 самих файлов. Совпали — сборки побайтно одинаковы.
Нет — по записям: каких нет в одной из сборок, у каких другое содержимое
(SHA-256 распакованного, размер) и у каких те же байты, но иные поля zip
(время, метод сжатия, атрибуты). Подписи нет ни в одной сборке без
ключа (D-35), и сравниваются именно неподписанные APK: подпись — шаг
после сборки.

Код возврата: 0 — побайтно одинаковы; 1 — различаются (что именно — в
выводе); 2 — файла нет или это не zip.
"""
import hashlib
import sys
import zipfile


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entries(path):
    """Имя записи → (SHA-256 содержимого, размер, поля zip, которые не содержимое)."""
    out = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            data = z.read(info)
            # Смещение и поле extra (выравнивание zipalign) — следствие длины записей
            # раньше: различие в одной записи сдвинуло бы все следующие.
            meta = (info.date_time, info.compress_type, info.external_attr)
            out[info.filename] = (hashlib.sha256(data).hexdigest(), len(data), meta)
    return out


def compare(a, b):
    """Строки отчёта о различиях записей; пусто — содержимое и поля одинаковы."""
    ea, eb = entries(a), entries(b)
    lines = []
    for name in sorted(ea.keys() - eb.keys()):
        lines.append(f"  только в первой: {name}")
    for name in sorted(eb.keys() - ea.keys()):
        lines.append(f"  только во второй: {name}")
    for name in sorted(ea.keys() & eb.keys()):
        (ha, sa, ma), (hb, sb, mb) = ea[name], eb[name]
        if ha != hb:
            lines.append(f"  другое содержимое: {name} ({sa} и {sb} байт)")
        elif ma != mb:
            lines.append(f"  те же байты, другие поля zip: {name}")
    return lines


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2].strip())
        return 2
    a, b = argv[1], argv[2]
    try:
        ha, hb = sha256_file(a), sha256_file(b)
        if ha == hb:
            print(f"✓ сборки побайтно одинаковы: SHA-256 {ha}")
            return 0
        lines = compare(a, b)
    except (OSError, zipfile.BadZipFile) as e:
        print(f"✗ не прочитать: {e}")
        return 2
    print(f"✗ сборки различаются: SHA-256 {ha} и {hb}")
    print("\n".join(lines) if lines else "  записи и их поля одинаковы — различие в служебных частях zip (оглавление, выравнивание)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
