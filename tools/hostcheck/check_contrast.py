#!/usr/bin/env python3
"""Контраст цветовых токенов интерфейса — по WCAG 2.2, уровень AA (D-34).

Читает `app/src/main/res/values/colors.xml` (светлая тема) и
`values-night/colors.xml` (тёмная) и проверяет в обеих темах:

  * у тем один и тот же набор токенов (D-34: «те же имена»);
  * каждая пара из [PAIRS] — цвет поверх фона, как они стоят в
    интерфейсе, — не ниже своего порога: текст — 4,5:1 (WCAG 1.4.3),
    граница или состояние элемента управления — 3:1 (WCAG 1.4.11);
  * цвета пар непрозрачны: контраст полупрозрачного зависит от того,
    что под ним, и токеном не задаётся.

Пары — список с причиной каждой, как разрешения в `check_manifest.py`:
новое сочетание в коде экранов — строка здесь. Не проверяются украшения,
которые ничего не обозначают: разделители, обводка карточки и ручка
нижнего листа — токен `outline`; у элементов управления граница —
`outline_strong`.

    python3 tools/hostcheck/check_contrast.py

Код возврата: 0 — чисто; 1 — нарушения; 2 — нет файла цветов.
"""
import os
import sys
import xml.etree.ElementTree as ET

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RES = os.path.join(PROJ, "app", "src", "main", "res")
THEMES = {
    "светлая": os.path.join(RES, "values", "colors.xml"),
    "тёмная": os.path.join(RES, "values-night", "colors.xml"),
}

TEXT = 4.5
UI = 3.0

# (цвет, фон, порог, где так стоит в интерфейсе)
PAIRS = [
    ("text", "bg", TEXT, "основной текст на фоне экрана"),
    ("text", "surface", TEXT, "основной текст на карточке и нижнем листе"),
    ("text", "surface_variant", TEXT, "введённый текст в поле"),
    ("text_secondary", "bg", TEXT, "вторичный текст на фоне, подпись невыбранной вкладки"),
    ("text_secondary", "surface", TEXT, "подписи строк, значки строк, невыбранная радиокнопка"),
    ("text_secondary", "surface_variant", TEXT, "подсказка поля, невыбранный сегмент, серая плашка"),
    ("primary", "bg", TEXT, "кнопка питания и заголовок «подключено» на фоне экрана"),
    ("primary", "surface", TEXT, "кнопки «текст» и «контур», вердикт, выбранная радиокнопка, бегунок включённого переключателя"),
    ("error", "bg", TEXT, "текст отказа на фоне экрана"),
    ("error", "surface", TEXT, "текст отказа на карточке"),
    ("warning", "bg", TEXT, "предупреждение на фоне экрана"),
    ("warning", "surface", TEXT, "предупреждение на карточке"),
    ("on_primary", "primary", TEXT, "основная кнопка, значок кнопки питания при подключении"),
    ("on_primary_container", "primary_container", TEXT, "тональная кнопка, плашка «подключено», выбранная вкладка, буква сервера"),
    ("success", "success_container", TEXT, "плашка «в порядке», «активна», задержка «хорошо»"),
    ("warning", "warning_container", TEXT, "плашка и задержка «средне»"),
    ("error", "error_container", TEXT, "плашка и задержка «плохо», «отказ»; кнопка питания при отказе"),
    ("outline_strong", "bg", UI, "граница кнопки «контур» на фоне экрана"),
    ("outline_strong", "surface", UI, "граница кнопки «контур» на карточке; бегунок выключенного переключателя"),
]


def luminance(argb):
    """Относительная яркость sRGB по WCAG 2.2."""
    def channel(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (argb >> 16) & 0xFF, (argb >> 8) & 0xFF, argb & 0xFF
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def ratio(a, b):
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def parse(value):
    """`#RRGGBB` или `#AARRGGBB` → ARGB; иначе None."""
    if not value or not value.startswith("#") or len(value) not in (7, 9):
        return None
    try:
        v = int(value[1:], 16)
    except ValueError:
        return None
    return v | 0xFF000000 if len(value) == 7 else v


def load(path):
    colors = {}
    for c in ET.parse(path).getroot().iter("color"):
        colors[c.get("name")] = (c.text or "").strip()
    return colors


def main():
    themes = {}
    for theme, path in THEMES.items():
        if not os.path.isfile(path):
            print(f"✗ check_contrast: нет {os.path.relpath(path, PROJ)}")
            return 2
        themes[theme] = load(path)
    problems = []
    names = [set(t) for t in themes.values()]
    if names[0] != names[1]:
        problems.append(f"темы с разными токенами: только в светлой — {sorted(names[0] - names[1])}, только в тёмной — {sorted(names[1] - names[0])}")
    worst = {TEXT: None, UI: None}
    for theme, colors in themes.items():
        for fg, bg, need, where in PAIRS:
            values = [parse(colors.get(fg)), parse(colors.get(bg))]
            if None in values:
                problems.append(f"{theme}: нет токена {fg if values[0] is None else bg} или он не цвет #RRGGBB/#AARRGGBB ({where})")
                continue
            if any(v >> 24 != 0xFF for v in values):
                problems.append(f"{theme}: {fg} на {bg} — полупрозрачный цвет, контраст не задан ({where})")
                continue
            r = ratio(*values)
            if r < need:
                problems.append(f"{theme}: {fg} на {bg} — {r:.2f}:1, нужно не ниже {need:g}:1 ({where})")
            if worst[need] is None or r < worst[need][0]:
                worst[need] = (r, f"{theme}: {fg} на {bg}")
    if problems:
        print("✗ Контраст:")
        for p in problems:
            print("    " + p)
        return 1
    print(
        f"✓ Контраст: {len(PAIRS)} пар в светлой и тёмной теме — текст не ниже {TEXT:g}:1 (меньше всего {worst[TEXT][0]:.2f}:1, {worst[TEXT][1]}), "
        f"границы и состояния элементов — не ниже {UI:g}:1 (меньше всего {worst[UI][0]:.2f}:1, {worst[UI][1]})",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
