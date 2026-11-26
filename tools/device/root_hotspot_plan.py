"""D-120: команды ROOT-шлюза из Kotlin-источников, без второй копии плана.

Стенд на телефоне выполняет ровно те строки, которые описаны в
RootHotspotRoutes.kt и RootHotspotInputGuard.kt.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app/src/main/kotlin/com/dpsmpx/dppass/app"
NAME = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")


def _list(text, name):
    body = re.search(rf"val {name} = listOf\((.*?)\n    \)", text, re.S)
    if not body:
        raise RuntimeError(f"нет списка {name}")
    return re.findall(r'"([^"]+)"', body.group(1))


def _value(text, name):
    found = re.search(rf'val {name} = "([^"]+)"', text)
    if not found:
        raise RuntimeError(f"нет строки {name}")
    return found.group(1)


def routes(downstream, tun, table, priority):
    if not (NAME.fullmatch(downstream) and NAME.fullmatch(tun)) or "lo" in (downstream, tun) or downstream == tun:
        raise ValueError("недопустимое имя интерфейса")
    if not (10_000 <= table <= 20_000 and 100 <= priority <= 999):
        raise ValueError("недопустимые таблица или приоритет")
    text = (APP / "RootHotspotRoutes.kt").read_text(encoding="utf-8")

    def fill(line):
        return (line.replace("${priority + 1}", str(priority + 1)).replace("$priority", str(priority))
                .replace("$downstream", downstream).replace("$tun", tun).replace("$table", str(table)))

    vacant = text.split('val checkVacant = """', 1)[1].split('"""', 1)[0]
    vacant = "\n".join(l[8:] if l.startswith("        ") else l for l in vacant.splitlines())
    vacant = vacant.replace("${'$'}", "$").replace("$priority", str(priority)).replace("$table", str(table))
    return {
        "check_vacant": vacant.strip() + "\n",
        "guard": [fill(l) for l in _list(text, "guard")],
        "attach": fill(_value(text, "attach")),
        "detach": fill(_value(text, "detach")),
        "retire": [fill(l) for l in _list(text, "retireAfterAccessPointStopped")],
    }


def input_guard(downstream, generation):
    if not NAME.fullmatch(downstream) or downstream == "lo" or not re.fullmatch(r"[a-f0-9]{16}", generation):
        raise ValueError("недопустимые параметры входного фильтра")
    text = (APP / "RootHotspotInputGuard.kt").read_text(encoding="utf-8")
    client = _value(text, "client").replace("$downstream", downstream).replace("$generation", generation)
    dhcp = _value(text, "dhcp").replace("$client", client)
    block = _value(text, "block").replace("$client", client)

    def fill(line):
        return line.replace("$dhcp", dhcp).replace("$block", block)

    return {
        "install": [fill(l) for l in _list(text, "install")],
        "retire": [fill(l) for l in _list(text, "retireAfterAccessPointStopped")],
        "marker": f"dppass-hotspot-{generation}",
    }
