#!/usr/bin/env python3
"""Туннель оболочки Linux на настоящем ядре (D-74, T4, T17).

    python3 tools/desktop/netns_check.py [--dist DIR]

DIR — собранный пакет (`./gradlew :desktop:installDist`, по умолчанию
desktop/build/install/dppass-desktop). Нужны root (свои пространства имён,
setpriv), iproute2 и Java 17+; без них — код 3 с причиной, а не пропуск.

1. Туннель. В пустом сетевом пространстве имён — «домашняя сеть»: интерфейс
   up0 (TUN без процесса — модулей dummy и veth может не быть) с адресом
   192.168.77.2/24 и маршрутом по умолчанию. `dppass-desktop --self-check`
   поднимает туннель тем же кодом, что окно, и спрашивает ядро `ip route
   get`. Сверяется: обычный трафик → dppass0; сокет с меткой ядра → up0;
   локальная сеть → up0; DNS к роутеру (UDP и TCP) → dppass0; DNS с меткой →
   up0; IPv6 — так же, если он есть в ядре; метка на fd не сокета — ENOTSOCK.
   Ядро Xray запускается на этом TUN дважды подряд (копия fd, D-74), а
   соединение, ушедшее в туннель, доходит до ядра: оно звонит серверу, и
   сокет проходит защитника. После закрытия — ни правил 7350–7353, ни dppass0.
2. Запуск с правами. Копия dppass-launch с заменой цели на пробу: процесс —
   от пользователя nobody, CapEff, CapAmb и CapBnd — только CAP_NET_ADMIN,
   NoNewPrivs, окружение — только разрешённое; DISPLAY не локальный и
   XAUTHORITY вне каталога сеанса отбрасываются; без PKEXEC_UID и с uid 0 —
   отказ.

Код возврата: 0 — всё сошлось; 1 — расхождение; 3 — нечем проверить.
"""
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DIST = os.path.join(PROJ, "desktop", "build", "install", "dppass-desktop")
LAUNCH = os.path.join(PROJ, "desktop", "package", "dppass-launch")
TARGET = "/usr/lib/dppass/bin/dppass-desktop"
NET_ADMIN = 1 << 12

UPLINK = """set -e
ip link set lo up
ip tuntap add dev up0 mode tun
ip addr add 192.168.77.2/24 dev up0
ip link set up0 up
ip route add default dev up0
if [ -e /proc/net/if_inet6 ]; then
  ip -6 addr add 2001:db8:77::2/64 dev up0 nodad
  ip -6 route add default dev up0
fi
"""

# Проба → интерфейс, на который ядро должно отправить пакет.
EXPECT = {
    "internet": "dppass0",
    "internet_marked": "up0",
    "lan": "up0",
    "lan_dns_udp": "dppass0",
    "lan_dns_tcp": "dppass0",
    "lan_dns_marked": "up0",
}
EXPECT6 = {"internet6": "dppass0", "internet6_marked": "up0"}
ENOTSOCK = 88


class Missing(Exception):
    pass


def need_tools():
    if os.geteuid() != 0:
        raise Missing("нужен root: своё сетевое пространство имён и setpriv")
    for tool in ("ip", "unshare", "setpriv", "getent", "java"):
        if shutil.which(tool) is None:
            raise Missing(f"нет {tool}")


def dev_of(output):
    words = output.split()
    return words[words.index("dev") + 1] if "dev" in words else None


def check_tunnel(dist, problems, notes):
    binary = os.path.join(dist, "bin", "dppass-desktop")
    if not os.access(binary, os.X_OK):
        raise Missing(f"нет пакета {dist}: ./gradlew :desktop:installDist")
    with tempfile.TemporaryDirectory() as tmp:
        report_path = os.path.join(tmp, "report.json")
        script = UPLINK + f'exec "{binary}" --self-check "{report_path}"\n'
        r = subprocess.run(["unshare", "--net", "--", "sh", "-c", script], capture_output=True, text=True, timeout=180)
        if not os.path.isfile(report_path):
            problems.append(f"self-check не написал отчёт (код {r.returncode}): {(r.stdout + r.stderr).strip()[-800:]}")
            return
        with open(report_path, encoding="utf-8") as f:
            rep = json.load(f)
    if rep.get("establish") != "ok":
        problems.append(f"туннель не поднялся: {rep.get('establish')}")
        return
    if not rep.get("net_admin"):
        problems.append("self-check без CAP_NET_ADMIN, хотя запущен от root")
    probes = rep["probes"]
    expect = dict(EXPECT)
    if rep.get("ipv6"):
        expect.update(EXPECT6)
    else:
        notes.append("IPv6 нет в ядре этой машины: ветка IPv6 не проверена (на ПК — TODO.md, «Linux — этап 6»)")
        if "inet6" in rep["link"]["output"]:
            problems.append("IPv6 выключен, а у dppass0 есть адрес IPv6")
    for name, want in expect.items():
        p = probes[name]
        got = dev_of(p["output"]) if p["code"] == 0 else None
        if got != want:
            problems.append(f"{name}: ядро ведёт через {got or '—'} ({p['output'].strip()[:160]}), ждали {want}")
    eng = rep.get("engine", {})
    for k in ("start1", "start2"):
        if eng.get(k) != "ok":
            problems.append(f"ядро Xray на TUN, запуск {k[-1]}: {eng.get(k) or eng.get('error')}")
    if eng.get("protected_sockets", 0) < 1:
        problems.append("соединение в туннель не дошло до ядра: ни один сокет ядра не прошёл защитника (метку)")
    if rep.get("mark_tun_fd") != -ENOTSOCK:
        problems.append(f"метка на fd TUN: {rep.get('mark_tun_fd')}, ждали −ENOTSOCK (−{ENOTSOCK})")
    for key in ("rules4_after", "rules6_after"):
        out = rep[key]["output"]
        if any(f"{p}:" in out for p in ("7350", "7351", "7352", "7353")):
            problems.append(f"после закрытия остались правила: {key}\n{out}")
    if rep["link_after"]["code"] == 0:
        problems.append("после закрытия dppass0 остался")


def run_launch(launcher, args, env):
    r = subprocess.run(["sh", launcher, *args], env=env, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


def check_launch(problems):
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o755)
        probe = os.path.join(tmp, "probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nid -u\ngrep -E '^(CapEff|CapAmb|CapBnd|NoNewPrivs):' /proc/self/status\necho ---\nenv\n")
        os.chmod(probe, 0o755)
        launcher = os.path.join(tmp, "dppass-launch")
        with open(LAUNCH, encoding="utf-8") as f:
            text = f.read()
        if text.count(TARGET) != 1:
            problems.append(f"dppass-launch: цель {TARGET} — не ровно одна")
            return
        with open(launcher, "w", encoding="utf-8") as f:
            f.write(text.replace(TARGET, probe))
        os.chmod(launcher, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        uid = subprocess.run(["id", "-u", "nobody"], capture_output=True, text=True).stdout.strip()
        base = {"PATH": "/usr/bin:/bin"}
        code, out, err = run_launch(launcher, [":0", "wayland-0", "/etc/shadow"], dict(base, PKEXEC_UID=uid, SECRET_TOKEN="x"))
        if code != 0:
            problems.append(f"dppass-launch от nobody: код {code}: {err.strip()}")
            return
        head, _, envtext = out.partition("---\n")
        lines = head.split()
        if not lines or lines[0] != uid:
            problems.append(f"процесс не от nobody: {head.strip()}")
        caps = dict(line.split(":\t") for line in head.strip().splitlines()[1:])
        for k in ("CapEff", "CapAmb", "CapBnd"):
            if int(caps.get(k, "0"), 16) != NET_ADMIN:
                problems.append(f"{k} = {caps.get(k)}, ждали только CAP_NET_ADMIN (0x1000)")
        if caps.get("NoNewPrivs", "").strip() != "1":
            problems.append("NoNewPrivs не 1")
        env = dict(line.split("=", 1) for line in envtext.splitlines() if "=" in line)
        if env.get("DISPLAY") != ":0" or env.get("WAYLAND_DISPLAY") != "wayland-0":
            problems.append(f"переменные окна не переданы: DISPLAY={env.get('DISPLAY')} WAYLAND_DISPLAY={env.get('WAYLAND_DISPLAY')}")
        if "XAUTHORITY" in env:
            problems.append(f"XAUTHORITY вне каталога сеанса принят: {env['XAUTHORITY']}")
        if "SECRET_TOKEN" in env or "PKEXEC_UID" in env:
            problems.append("окружение вызвавшего прошло в процесс окна")
        # Не локальный DISPLAY — отбрасывается.
        code, out, _ = run_launch(launcher, ["evil.example:0", "../wayland", ""], dict(base, PKEXEC_UID=uid))
        env2 = dict(line.split("=", 1) for line in out.partition("---\n")[2].splitlines() if "=" in line)
        if code != 0 or "DISPLAY" in env2 or "WAYLAND_DISPLAY" in env2:
            problems.append(f"не локальный DISPLAY или путь в WAYLAND_DISPLAY приняты (код {code})")
        for bad_env, what in ((base, "без PKEXEC_UID"), (dict(base, PKEXEC_UID="0"), "с uid 0"), (dict(base, PKEXEC_UID="1x"), "с PKEXEC_UID не числом")):
            code, _, _ = run_launch(launcher, [], bad_env)
            if code != 2:
                problems.append(f"dppass-launch {what}: код {code}, ждали 2")


def main(argv):
    ap = argparse.ArgumentParser(prog="netns_check.py", description="туннель оболочки Linux на настоящем ядре (D-74)")
    ap.add_argument("--dist", default=DEFAULT_DIST)
    args = ap.parse_args(argv)
    problems, notes = [], []
    try:
        need_tools()
        check_tunnel(os.path.abspath(args.dist), problems, notes)
        check_launch(problems)
    except Missing as e:
        print(f"✗ нечем проверить: {e}")
        return 3
    for n in notes:
        print(f"! {n}")
    if problems:
        for p in problems:
            print(f"✗ {p}")
        return 1
    print("✓ туннель Linux: TUN, адреса, маршруты, правила, метка, ядро Xray на TUN и уборка на настоящем ядре; "
          "dppass-launch — nobody с одной CAP_NET_ADMIN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
