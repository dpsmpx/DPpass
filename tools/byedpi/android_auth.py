"""Session-scoped SOCKS5 authentication in Android VPN mode; no DPI algorithm changes."""
from pathlib import Path

def patch(path: Path):
    s = path.read_text()
    def replace(old, new):
        nonlocal s
        if s.count(old) != 1:
            raise RuntimeError("Pinned ByeDPI source changed: " + old[:40])
        s = s.replace(old, new)
    replace("    uint8_t c = S_AUTH_BAD;", """    const char *token = getenv("DPPASS_SOCKS_TOKEN");
    uint8_t wanted = token ? 2 : S_AUTH_NONE;
    uint8_t c = S_AUTH_BAD;""")
    replace("        if (buffer[i] == S_AUTH_NONE) {\n            c = S_AUTH_NONE;", "        if ((uint8_t)buffer[i] == wanted) {\n            c = wanted;")
    replace("    if (*buff->data == S_VER5) {", """    const char *token = getenv("DPPASS_SOCKS_TOKEN");
    if (token && val->flag == 99) {
        const unsigned char *a = (const unsigned char *)buff->data;
        int good = n >= 9 && a[0] == 1 && a[1] == 6 &&
            !memcmp(a + 2, "dppass", 6) &&
            a[8] == strlen(token) && n == 9 + a[8] &&
            !memcmp(a + 9, token, a[8]);
        unsigned char reply[2] = {1, good ? 0 : 1};
        if (send(val->fd, (char *)reply, 2, 0) != 2 || !good) return -1;
        val->flag = FLAG_S5;
        return 0;
    }
    if (token && *buff->data != S_VER5) return -1;
    if (*buff->data == S_VER5) {""")
    replace("            val->flag = FLAG_S5;\n            return 0;", "            val->flag = token ? 99 : FLAG_S5;\n            return 0;")
    path.write_text(s)
