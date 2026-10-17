#!/usr/bin/env python3
"""Текстовые файлы — без невидимых символов и табуляций в отступе.

Жёсткие минимумы формата; стиль кода Kotlin (длина строк, переносы,
отступы) — дело форматтера: ktlint, задача `ktlintCheck` (D-63). UTF-8, LF (`*.bat` — CRLF, так их
генерирует Gradle), перевод строки в конце и хвостовые пробелы проверяет
DP Verify — `format.text` в `tools/dpverify.toml` (D-50). Здесь — то, чего
у него нет, во всех текстовых файлах, которые попадут в коммит:

  * без одиночного CR (старый перевод строки Mac);
  * без табуляций для отступа (исключение — исходники Go `*.go`, `go.mod`:
    их вид задаёт `gofmt`, а он отступает табуляцией; `tools/xray/`);
  * без невидимых и управляющих направлением письма символов: BOM
    (U+FEFF), нулевой ширины (U+200B…U+200F), мягкий перенос (U+00AD),
    разделители U+2028/U+2029, двунаправленные U+202A…U+202E и
    U+2066…U+2069. Последние меняют порядок показа текста: код выглядит
    в обзоре не так, как его читает компилятор (атака Trojan Source,
    CVE-2021-42574). Настоящий BOM в строке Kotlin пишется как `\\uFEFF`.

Корпус `tests/data/` не проверяется: его байты — предмет теста.

    python3 tools/hostcheck/check_format.py

Код возврата: 0 — чисто; 1 — нарушения.
"""
import os
import re
import subprocess
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKIP_PREFIXES = ("tests/data/",)
# gofmt — единственный формат исходников Go, и отступ в нём — табуляция.
TAB_INDENT_ALLOWED = (".go", "/go.mod")
INVISIBLE = re.compile("[\ufeff\u200b-\u200f\u00ad\u2028\u2029\u202a-\u202e\u2066-\u2069]")
NAMES = {
    "\ufeff": "BOM U+FEFF", "\u00ad": "мягкий перенос U+00AD",
    "\u2028": "разделитель строк U+2028", "\u2029": "разделитель абзацев U+2029",
}


def describe(ch):
    code = ord(ch)
    if ch in NAMES:
        return NAMES[ch]
    if 0x200B <= code <= 0x200F:
        return f"символ нулевой ширины U+{code:04X}"
    return f"управление направлением письма U+{code:04X}"


def files():
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=PROJ, capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    return sorted(p for p in out if p and os.path.isfile(os.path.join(PROJ, p)))


def main():
    problems, scanned = [], 0
    for rel in files():
        if rel.startswith(SKIP_PREFIXES):
            continue
        with open(os.path.join(PROJ, rel), "rb") as f:
            raw = f.read()
        if b"\0" in raw[:8192]:
            continue  # двоичный файл: его происхождение — docs/PROVENANCE.md
        scanned += 1
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue  # не UTF-8 — находка format.text
        if re.search("\r(?!\n)", text):
            problems.append(f"{rel}: одиночный CR — нужен LF")
        for n, line in enumerate(text.split("\n"), 1):
            line = line.rstrip("\r")
            m = INVISIBLE.search(line)
            if m:
                problems.append(f"{rel}:{n}: {describe(m.group(0))}, столбец {m.start() + 1}")
            if (line.startswith("\t") or re.match(r"^ *\t", line)) and not rel.endswith(TAB_INDENT_ALLOWED):
                problems.append(f"{rel}:{n}: табуляция в отступе")
    if problems:
        print("✗ Формат:")
        for p in problems:
            print("    " + p)
        print("  Минимумы формата — tools/hostcheck/check_format.py; корпус tests/data не проверяется.")
        return 1
    print(f"✓ Формат: {scanned} текстовых файлов — без невидимых символов, одиночного CR и табуляций в отступе")
    return 0


if __name__ == "__main__":
    sys.exit(main())
