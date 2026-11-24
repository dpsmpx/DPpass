"""Host-side real upstream executable startup/auth test; no external network."""
import os
import socket
import subprocess
import time

def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("unexpected SOCKS EOF")
        data += chunk
    return data

def smoke(binary, path):
    token = "a" * 48
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    args = [str(binary), "--ip", "127.0.0.1", "--port", str(port),
            "--protect-path", str(path), "--no-domain", "--auto=torst",
            "--timeout", "3", "--split", "1", "--tlsrec", "1+s"]
    proc = subprocess.Popen(args, env={**os.environ, "DPPASS_SOCKS_TOKEN": token},
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None:
                raise RuntimeError("ciadpi exited: " + proc.stderr.read().decode(errors="replace"))
            try:
                peer = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        with peer:
            peer.sendall(b"\x05\x01\x02")
            assert read_exact(peer, 2) == b"\x05\x02"
            peer.sendall(b"\x01\x06dppass\x30" + token.encode())
            assert read_exact(peer, 2) == b"\x01\x00"
        with socket.create_connection(("127.0.0.1", port), timeout=1) as peer:
            peer.sendall(b"\x05\x01\x00")
            assert read_exact(peer, 2) == b"\x05\xff"
        with socket.create_connection(("127.0.0.1", port), timeout=1) as peer:
            peer.sendall(b"\x05\x01\x02")
            assert read_exact(peer, 2) == b"\x05\x02"
            peer.sendall(b"\x01\x06dppass\x30" + b"b" * 48)
            assert read_exact(peer, 2) == b"\x01\x01"
        print("ByeDPI native startup and authenticated SOCKS5 smoke test passed")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        proc.stderr.close()
