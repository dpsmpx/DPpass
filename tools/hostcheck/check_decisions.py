#!/usr/bin/env python3
"""Журнал решений: номера по порядку и «следующий свободный» в шапке.

`process.files` DP Verify (D-50) проверяет номера и поле «Проверка», но не
шапку: после D-51 «следующий свободный номер» отстал от журнала, и это
заметили глазами (6 октября 2026), а после D-98 — снова. Здесь — то, чего у
DP Verify нет:

  * заголовки решений `### D-NN` идут по порядку с D-01, без пропусков и
    повторов;
  * в шапке «следующий свободный номер (сейчас — **N**)» N — последний
    номер плюс один.

    python3 tools/hostcheck/check_decisions.py

Код возврата: 0 — журнал согласован; 1 — нет; 2 — нет файла или шапки.
"""
import os
import re
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DECISIONS = os.path.join(PROJ, "docs", "direction", "DECISIONS.md")
HEADING = re.compile(r"^### D-(\d+)\b", re.M)
NEXT = re.compile(r"следующий\s+свободный\s+номер\s+\(сейчас\s+—\s+\*\*(\d+)\*\*\)")


def check(text):
    """Находки по тексту журнала; пустой список — согласован. None — шапки нет."""
    numbers = [int(n) for n in HEADING.findall(text)]
    m = NEXT.search(" ".join(text.split()))
    if m is None:
        return None
    problems = []
    for i, n in enumerate(numbers, 1):
        if n != i:
            problems.append(f"решение номер {i} по порядку — D-{n:02d}: номера идут с D-01 без пропусков и повторов")
            break
    want = (numbers[-1] + 1) if numbers else 1
    if int(m.group(1)) != want:
        problems.append(f"в шапке «следующий свободный номер» — {m.group(1)}, а по журналу — {want} (последнее — D-{want - 1:02d})")
    return problems


def main():
    if not os.path.isfile(DECISIONS):
        print("✗ нет docs/direction/DECISIONS.md")
        return 2
    with open(DECISIONS, encoding="utf-8") as f:
        text = f.read()
    problems = check(text)
    if problems is None:
        print("✗ в шапке DECISIONS.md нет «следующий свободный номер (сейчас — **N**)»")
        return 2
    if problems:
        print("✗ Журнал решений:")
        for p in problems:
            print("    " + p)
        return 1
    n = len(HEADING.findall(text))
    print(f"✓ Журнал решений: D-01…D-{n:02d} по порядку, следующий свободный в шапке — {n + 1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
