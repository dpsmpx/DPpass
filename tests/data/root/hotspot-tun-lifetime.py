#!/usr/bin/env python3
"""D-120: проверка непостоянного TUN (unshare -Urn python3 <файл>)."""
import array
import fcntl
import os
import select
import socket
import struct
import subprocess


def ip(*args):
    return subprocess.check_output(["ip", *args], text=True)


def main():
    links = ip("-o", "link", "show").splitlines()
    if len(links) != 1 or not links[0].startswith("1: lo:"):
        raise SystemExit("expected fresh network namespace")

    # IFF_TUN | IFF_NO_PI: ядро отправляет IPv4 без служебного заголовка.
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH22x", b"dpgateway", 0x1001))
        # Не даём IPv6 DAD отправить первый пакет раньше тестового UDP.
        with open("/proc/sys/net/ipv6/conf/dpgateway/disable_ipv6", "w") as knob:
            knob.write("1\n")
        ip("address", "add", "192.0.2.1/24", "dev", "dpgateway")
        ip("link", "set", "dpgateway", "up")
        # SCM_RIGHTS сохраняет ссылку на TUN после закрытия исходного fd.
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with tx, rx:
            tx.sendmsg([b"T"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
            received = array.array("i")
            data, ancillary, flags, _ = rx.recvmsg(1, socket.CMSG_SPACE(received.itemsize), socket.MSG_CMSG_CLOEXEC)
            assert data == b"T" and not flags & socket.MSG_CTRUNC
            assert len(ancillary) == 1
            level, kind, raw = ancillary[0]
            assert (level, kind, len(raw)) == (socket.SOL_SOCKET, socket.SCM_RIGHTS, received.itemsize)
            received.frombytes(raw)
            os.close(fd)
            fd = received[0]
            assert not os.get_inheritable(fd)
        payload = b"synthetic-tun-payload"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(payload, ("192.0.2.2", 5353))
            readable, _, _ = select.select([fd], [], [], 2)
            if not readable:
                raise AssertionError("packet did not reach TUN")
            packet = os.read(fd, 65535)
            assert packet[0] == 0x45 and packet[9] == socket.IPPROTO_UDP
            assert packet[16:20] == socket.inet_aton("192.0.2.2")
            assert struct.unpack_from("!H", packet, 22)[0] == 5353
            assert packet[28:] == payload
    finally:
        os.close(fd)

    assert "dpgateway" not in ip("-o", "link", "show")
    print("hotspot private TUN: packet and descriptor lifetime passed")


if __name__ == "__main__":
    main()
