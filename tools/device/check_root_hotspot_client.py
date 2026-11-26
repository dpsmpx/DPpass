#!/usr/bin/env python3
"""D-120: поднять временную локальную AP на Zenfone и подключить к ней клиента.

Пароль AP читается из приватного каталога DPpass через ROOT и не печатается.
После проверки тестовая сеть удаляется на клиенте, AP останавливается.
"""
import argparse
import re
import secrets
import root_hotspot_plan as plan
import subprocess
import time

PKG = "com.dpsmpx.dppass"
INFO = f"/data/user/0/{PKG}/cache/dppass-lab-ap"
RUNNER = f"{PKG}.test/{PKG}.app.device.DeviceTestRunner"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--router", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--guard", action="store_true", help="install the D-120 guard on the AP interface")
    parser.add_argument("--tun-helper", help="ARM64 helper: dispatch a client test flow into a blackhole TUN")
    parser.add_argument('--local-baseline', action='store_true', help='Test captured freedom egress (not DPI strategies)')
    args = parser.parse_args()
    if args.local_baseline and not args.tun_helper:
        parser.error('--local-baseline requires --tun-helper')
    if args.tun_helper and not args.guard:
        parser.error("--tun-helper requires --guard")
    case = "clientThroughTun" if args.tun_helper else "holdAccessPoint"
    if args.local_baseline:
        case = 'clientThroughLocal'
    staging = None
    attached = []

    def adb(serial, *command, check=True, timeout=30):
        return subprocess.run([args.adb, "-s", serial, *command], capture_output=True,
                              encoding="utf-8", timeout=timeout, check=check)

    def router_root(script, check=True):
        return adb(args.router, "shell", f"su -c '{script}'", check=check)

    def router_root_script(script, check=False):
        # Скрипт через stdin: без вложенных кавычек оболочки adb и su.
        return subprocess.run([args.adb, "-s", args.router, "shell", "-T", "su -c 'sh -s'"],
                              input=script, capture_output=True, encoding="utf-8", timeout=30, check=check)

    installed = []
    guard_down = None
    routes = inputs = forwards = None

    if adb(args.router, "shell", "getprop ro.product.model").stdout.strip() != "Zenfone Max Pro M1":
        raise SystemExit("Expected Zenfone Max Pro M1 as router")
    location = adb(args.router, "shell", "settings get secure location_mode").stdout.strip()
    if not re.fullmatch(r"[0-3]", location):
        raise SystemExit("Unexpected location mode")
    for permission in ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"):
        adb(args.router, "shell", f"pm grant {PKG} android.permission.{permission}")

    ssid = None
    network_id = None
    process = None
    try:
        adb(args.router, "shell", "settings put secure location_mode 3")
        process = subprocess.Popen(
            [args.adb, "-s", args.router, "shell", "am", "instrument", "-w", "-e", "tests",
             f"RootHotspotManual.{case}", RUNNER],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8")
        deadline = time.monotonic() + 30
        lines = []
        while time.monotonic() < deadline and process.poll() is None:
            read = router_root(f"cat {INFO}", check=False)
            lines = read.stdout.splitlines()
            if read.returncode == 0 and len(lines) == 2 and all(lines):
                break
            time.sleep(0.5)
        if len(lines) != 2:
            raise SystemExit("Access point did not start")
        ssid, passphrase = lines
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", ssid) or not re.fullmatch(r"[A-Za-z0-9_-]{8,63}", passphrase):
            raise SystemExit("Unexpected access point parameters")
        print(f"router: local-only AP started ({ssid})")

        before = adb(args.client, "shell", "cmd wifi list-networks").stdout
        adb(args.client, "shell", f"cmd wifi connect-network {ssid} wpa2 {passphrase}")
        after = adb(args.client, "shell", "cmd wifi list-networks").stdout
        for line in after.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1] == ssid and line not in before:
                network_id = fields[0]
        ok = False
        for _ in range(40):
            status = adb(args.client, "shell", "cmd wifi status").stdout
            if f'connected to "{ssid}"' in status:
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            raise SystemExit("Client did not associate with the test AP")
        client_addr = ""
        for _ in range(20):
            client_addr = adb(args.client, "shell", "ip -4 -o addr show wlan0").stdout
            if " inet " in client_addr:
                break
            time.sleep(0.5)
        client_ip = re.search(r" inet (\d+\.\d+\.\d+\.\d+)/(\d+)", client_addr)
        print("client: associated, IPv4", f"{client_ip.group(1)}/{client_ip.group(2)}" if client_ip else "missing")

        links = router_root("ip -4 -o addr show").stdout
        for line in links.splitlines():
            fields = line.split()
            if len(fields) > 3 and fields[1] != "lo":
                print("router iface:", fields[1], fields[3])
        tether = adb(args.router, "shell", "dumpsys tethering").stdout
        for line in tether.splitlines():
            if re.search(r" - \w+State - |Offload HALs not", line):
                print("router tethering:", line.strip())
        forward = router_root("cat /proc/sys/net/ipv4/ip_forward").stdout.strip()
        print("router ip_forward:", forward)
        # Исходное состояние без DPpass: локальная AP не должна давать интернет.
        gateway = None
        for line in links.splitlines():
            fields = line.split()
            if len(fields) > 3 and client_ip and fields[3].split("/")[0].rsplit(".", 1)[0] == client_ip.group(1).rsplit(".", 1)[0]:
                gateway = fields[3].split("/")[0]
        for label, target in (("gateway", gateway), ("internet", "1.1.1.1")):
            if target is None:
                print(f"client ping {label}: no target")
                continue
            ping = adb(args.client, "shell", f"ping -I wlan0 -c 2 -W 2 {target}", check=False, timeout=15)
            print(f"client ping {label}:", "reachable" if ping.returncode == 0 else "unreachable")
        v6 = adb(args.client, "shell", "ip -6 -o addr show wlan0 scope global", check=False).stdout.strip()
        print("client global IPv6:", "present" if v6 else "none")

        if args.guard:
            downstream = None
            for line in links.splitlines():
                fields = line.split()
                if len(fields) > 3 and gateway and fields[3].split("/")[0] == gateway:
                    downstream = fields[1]
            if downstream is None or not plan.NAME.fullmatch(downstream):
                raise SystemExit("AP interface not identified")
            local_only = re.findall(r"^\s*(\S+) - LocalHotspotState - lastError = 0\s*$", tether, re.M)
            if local_only != [downstream]:
                raise SystemExit("AP address does not identify the sole system local-only interface")
            generation = secrets.token_hex(8)
            routes = plan.routes(downstream, "dpgateway", 10120, 100)
            inputs = plan.input_guard(downstream, generation)
            forwards = plan.forward_guard(downstream, "dpgateway", generation)
            if router_root_script(routes["check_vacant"]).returncode != 0:
                raise SystemExit("Routing table or priority already in use")
            guard_down = downstream
            # Сначала INPUT и FORWARD DROP, затем маршрутные запреты: до lookup клиент уже без выхода.
            for command in inputs["install"] + forwards["install"] + routes["guard"]:
                installed.append(command)
                router_root_script(command + "\n", check=True)
            print(f"router: guard installed on {downstream}")
            for label, target in (("gateway", gateway), ("internet", "1.1.1.1")):
                ping = adb(args.client, "shell", f"ping -I wlan0 -c 2 -W 2 {target}", check=False, timeout=15)
                print(f"guarded client ping {label}:", "reachable" if ping.returncode == 0 else "unreachable")
            if args.tun_helper:
                tmp = adb(args.router, "shell", "mktemp -d /data/local/tmp/dppass-tun.XXXXXXXX").stdout.strip()
                if not re.fullmatch(r"/data/local/tmp/dppass-tun\.[A-Za-z0-9]{8}", tmp):
                    raise SystemExit("Invalid helper directory")
                staging = tmp
                adb(args.router, "push", args.tun_helper, tmp + "/probe")
                adb(args.router, "shell", f"chmod 700 {tmp}/probe")
                target = '1.1.1.1:443' if args.local_baseline else '192.0.2.2:5353'
                router_root_script(f"printf '%s\\n' {client_ip.group(1)} {target} > {INFO}.client\nchmod 644 {INFO}.client\n", check=True)
                router_root(f"{tmp}/probe send-main /data/user/0/{PKG}/cache/dppass-tun-probe.sock")
                for _ in range(30):
                    if router_root(f"test -s {INFO}.ready", check=False).returncode == 0:
                        break
                    time.sleep(.2)
                else:
                    raise SystemExit("Core not ready")
                for add, remove in zip(forwards['attach'] + [routes['attach']], forwards['detach'] + [routes['detach']]):
                    router_root_script(add + '\n', check=True)
                    attached.append(remove)
                if args.local_baseline:
                    probe = 'curl --interface wlan0 --noproxy "*" --connect-timeout 5 --max-time 10 --resolve one.one.one.one:443:1.1.1.1 -fsS https://one.one.one.one/cdn-cgi/trace'
                    response = adb(args.client, 'shell', probe, check=False)
                    if response.returncode or 'h=one.one.one.one' not in response.stdout.splitlines():
                        raise SystemExit(f'Captured HTTPS control failed (curl={response.returncode})')
                    print('client HTTPS control: verified')
                    router_root(f'touch {INFO}.kill')
                    for _ in range(30):
                        if router_root(f'test -s {INFO}.killed', check=False).returncode == 0:
                            break
                        time.sleep(.2)
                    else:
                        raise SystemExit('No confirmation of engine stop')
                    if adb(args.client, 'shell', probe, check=False).returncode == 0:
                        raise SystemExit('HTTPS still available after engine stop')
                    print('client HTTPS after engine stop: unavailable')
                elif adb(args.client, 'shell', 'curl --interface wlan0 --noproxy "*" -fsS --connect-timeout 3 --max-time 4 http://192.0.2.2:5353/ -o /dev/null', check=False).returncode == 0:
                    raise SystemExit('Unexpected response on blackhole path')
    finally:
        for remove in reversed(attached):
            router_root_script(remove + '\n', check=False)
        if staging:
            adb(args.router, 'shell', f'rm -f {staging}/probe && rmdir {staging}', check=False)
        if process is not None and guard_down is not None:
            # Порядок D-120: сначала остановить AP и подтвердить, затем снять защиту.
            router_root(f"touch {INFO}.stop", check=False)
            try:
                process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            process = None
            if args.tun_helper:
                seen = router_root(f"cat {INFO}.seen", check=False).stdout.strip()
                print("core saw client flow:", seen or "no report")
                router_root(f"rm -f {INFO}.seen {INFO}.client", check=False)
            stopped = False
            for _ in range(20):
                snapshot = adb(args.router, "shell", "dumpsys tethering", check=False)
                # Ошибка ADB, пустой вывод и смена типа раздачи не доказывают остановку.
                # На Zenfone wlan1 остаётся после остановки AP: проверяем снятие адреса AP.
                addr = router_root(f"ip -4 -o addr show dev {guard_down}", check=False)
                if (snapshot.returncode == 0 and "Tether state:" in snapshot.stdout
                        and not re.search(rf"^\s*{re.escape(guard_down)} - (?:LocalHotspot|Tethered)State", snapshot.stdout, re.M)
                        and addr.returncode == 0 and f" inet {gateway}/" not in addr.stdout):
                    stopped = True
                    break
                time.sleep(0.5)
            if stopped:
                retire = routes["retire"] + forwards["retire"] + inputs["retire"]
                for command in retire:
                    router_root_script(command + "\n", check=False)
                leftover = router_root_script(
                    f"ip -4 rule show | grep -c 'iif {guard_down}' ; ip -6 rule show | grep -c 'iif {guard_down}' ;"
                    f" iptables -S INPUT | grep -c {inputs['marker']} ; ip6tables -S INPUT | grep -c {inputs['marker']} ;"
                    f" iptables -S FORWARD | grep -c {inputs['marker']} ; ip6tables -S FORWARD | grep -c {inputs['marker']}\n",
                    check=False).stdout.split()
                print("router: guard retired, leftover counts", leftover)
            else:
                print("router: AP NOT confirmed stopped, guard RETAINED")
        if network_id is not None:
            adb(args.client, "shell", f"cmd wifi forget-network {network_id}", check=False)
        router_root(f"touch {INFO}.stop", check=False)
        if process is not None:
            try:
                out, _ = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                out, _ = process.communicate()
            print(out.strip().splitlines()[-1] if out.strip() else "instrumentation: no output")
        adb(args.router, "shell", f"settings put secure location_mode {location}", check=False)
        print("router location_mode restored:", adb(args.router, "shell", "settings get secure location_mode").stdout.strip())
        for _ in range(30):
            status = adb(args.client, "shell", "cmd wifi status").stdout
            if "connected to" in status and (ssid is None or f'"{ssid}"' not in status):
                break
            time.sleep(1)
        state = adb(args.client, "shell", "cmd wifi status").stdout
        print("client after test:", "reconnected to saved network" if "connected to" in state and (ssid is None or ssid not in state) else "NOT reconnected")


if __name__ == "__main__":
    main()
