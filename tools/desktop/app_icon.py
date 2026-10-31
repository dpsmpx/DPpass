#!/usr/bin/env python3
"""Значок dppass.exe (D-97): ICO из desktop/package/dppass.svg без новых зависимостей.

    python3 tools/desktop/app_icon.py OUT.ico

Преобразователя SVG в стандартной библиотеке нет, а рисунок — три фигуры
(D-01): круг с обводкой, дуга и отрезок с круглыми концами. Сценарий
читает ровно их; другой элемент, атрибут или команда пути — отказ, а не
«нарисовать похоже» (D-05): значок не разойдётся с SVG молча. Пиксель
закрашивается по расстоянию от его центра до края фигуры — сглаживание
без суперсэмплинга. ICO — с записями PNG (Windows Vista и новее); размеры —
те, что берёт Проводник. Вывод зависит только от SVG: две сборки дают одни
байты (комплект воспроизводится).

Тот же рисунок в окне и в области уведомлений — `ui/AppIcon.kt`.
"""
import math
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SVG = os.path.join(PROJ, "desktop", "package", "dppass.svg")
SIZES = [16, 24, 32, 48, 64, 256]
NS = "{http://www.w3.org/2000/svg}"
KNOWN = {
    "circle": {"cx", "cy", "r", "fill", "stroke", "stroke-width"},
    "path": {"d", "fill", "stroke", "stroke-width", "stroke-linecap"},
    "line": {"x1", "y1", "x2", "y2", "stroke", "stroke-width", "stroke-linecap"},
}


def color(text, where):
    if text is None or text == "none":
        return None
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", text):
        raise ValueError(f"{where}: цвет {text!r} — ожидался #RRGGBB или none")
    return tuple(int(text[i:i + 2], 16) for i in (1, 3, 5))


def number(el, name, where):
    try:
        return float(el.attrib[name])
    except (KeyError, ValueError):
        raise ValueError(f"{where}: нет числа {name}") from None


def round_cap(el, where):
    if el.get("stroke-linecap") != "round":
        raise ValueError(f"{where}: конец линии не round — такой не рисуется")


def arc_center(x1, y1, r, large, sweep, x2, y2, where):
    """Центр и углы дуги SVG (SVG 1.1, F.6.5) для окружности без поворота."""
    mx, my = (x1 - x2) / 2, (y1 - y2) / 2
    half = mx * mx + my * my
    if half == 0 or half > r * r:
        raise ValueError(f"{where}: дуга не помещается в радиус {r}")
    k = math.sqrt((r * r - half) / half) * (-1 if large == sweep else 1)
    cx, cy = k * my + (x1 + x2) / 2, -k * mx + (y1 + y2) / 2
    a1 = math.atan2(y1 - cy, x1 - cx)
    a2 = math.atan2(y2 - cy, x2 - cx)
    span = a2 - a1
    if sweep and span < 0:
        span += 2 * math.pi
    elif not sweep and span > 0:
        span -= 2 * math.pi
    return cx, cy, a1, span


def segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def shapes(path=SVG):
    """Фигуры SVG как (цвет, расстояние со знаком: меньше нуля — внутри) в порядке рисования."""
    root = ET.parse(path).getroot()
    if root.tag != NS + "svg" or root.get("viewBox") != "0 0 128 128":
        raise ValueError("dppass.svg: корень — svg с viewBox 0 0 128 128")
    out = []
    for i, el in enumerate(root):
        tag = el.tag.removeprefix(NS)
        where = f"dppass.svg, элемент {i + 1} ({tag})"
        if tag not in KNOWN:
            raise ValueError(f"{where}: такой элемент не рисуется")
        extra = set(el.attrib) - KNOWN[tag]
        if extra:
            raise ValueError(f"{where}: атрибуты {sorted(extra)} не рисуются")
        width = float(el.get("stroke-width", "0"))
        stroke = color(el.get("stroke"), where)
        if tag == "circle":
            cx, cy, r = (number(el, n, where) for n in ("cx", "cy", "r"))
            fill = color(el.get("fill"), where)
            if fill:
                out.append((fill, lambda x, y, cx=cx, cy=cy, r=r: math.hypot(x - cx, y - cy) - r))
            if stroke and width:
                out.append((stroke, lambda x, y, cx=cx, cy=cy, r=r, w=width: abs(math.hypot(x - cx, y - cy) - r) - w / 2))
        elif tag == "path":
            round_cap(el, where)
            if color(el.get("fill"), where):
                raise ValueError(f"{where}: заливка пути не рисуется")
            m = re.fullmatch(r"M\s*(\S+)\s+(\S+)\s+A\s*(\S+)\s+(\S+)\s+0\s+([01])\s+([01])\s+(\S+)\s+(\S+)", el.get("d", ""))
            if not m or m.group(3) != m.group(4):
                raise ValueError(f"{where}: путь — только «M x y A r r 0 большая направление x y»")
            x1, y1, r, _, large, sweep, x2, y2 = (float(g) for g in m.groups())
            cx, cy, a1, span = arc_center(x1, y1, r, int(large), int(sweep), x2, y2, where)

            def arc(x, y, cx=cx, cy=cy, r=r, a1=a1, span=span, w=width, ends=((x1, y1), (x2, y2))):
                t = (math.atan2(y - cy, x - cx) - a1) * (1 if span > 0 else -1) % (2 * math.pi)
                if t <= abs(span):
                    d = abs(math.hypot(x - cx, y - cy) - r)
                else:
                    d = min(math.hypot(x - ex, y - ey) for ex, ey in ends)
                return d - w / 2
            out.append((stroke, arc))
        else:
            round_cap(el, where)
            ax, ay, bx, by = (number(el, n, where) for n in ("x1", "y1", "x2", "y2"))
            out.append((stroke, lambda x, y, ax=ax, ay=ay, bx=bx, by=by, w=width: segment(x, y, ax, ay, bx, by) - w / 2))
        if out and out[-1][0] is None:
            raise ValueError(f"{where}: обводка без цвета")
    return out


def raster(figures, size):
    """RGBA построчно; покрытие пикселя — по расстоянию от его центра до края фигуры."""
    scale = 128 / size
    rows = []
    for j in range(size):
        row = bytearray()
        for i in range(size):
            x, y = (i + 0.5) * scale, (j + 0.5) * scale
            r = g = b = a = 0.0
            for rgb, dist in figures:
                cov = min(1.0, max(0.0, 0.5 - dist(x, y) / scale))
                if cov == 0:
                    continue
                na = cov + a * (1 - cov)
                r, g, b = ((c / 255 * cov + p * a * (1 - cov)) / na for c, p in zip(rgb, (r, g, b)))
                a = na
            row += bytes(round(v * 255) for v in (r, g, b, a))
        rows.append(bytes(row))
    return rows


def png(rows, size):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    raw = b"".join(b"\0" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(images):
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = len(head) + 16 * len(images)
    entries, body = b"", b""
    for size, data in images:
        side = 0 if size == 256 else size
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset + len(body))
        body += data
    return head + entries + body


def pngs(path=SVG):
    """(размер, PNG) для каждого размера ICO."""
    figures = shapes(path)
    return [(s, png(raster(figures, s), s)) for s in SIZES]


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    with open(argv[1], "wb") as f:
        f.write(ico(pngs()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
