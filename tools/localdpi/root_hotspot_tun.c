#define _GNU_SOURCE
#include "root_hotspot_tun.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define TUN_NAME "dpgateway"

/* Strict filesystem socket path, never an abstract or relative address.
 * Socket lives in an app-owned directory; peer credentials are mandatory. */
int dppass_hotspot_tun_socket_path(const char *path) {
    if (!path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 0;
    const char *part = path + 1;
    for (const char *p = part; ; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t n = (size_t)(p - part);
            if (n == 0 || (n == 1 && part[0] == '.') ||
                (n == 2 && part[0] == '.' && part[1] == '.')) return 0;
            if (!*p) break;
            part = p + 1;
        } else if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                     (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return 0;
    }
    return 1;
}

static int connect_owner(const char *path, uid_t uid, pid_t pid) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_uid != uid) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    memcpy(address.sun_path, path, strlen(path) + 1);
    // A full backlog or any ambiguous connect is a refusal, not a retry.
    if (connect(fd, (struct sockaddr *)&address, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1)) != 0)
        goto fail;
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
        size != sizeof(peer) || peer.uid != uid || peer.pid != pid) goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static int create_tun(void) {
    if (if_nametoindex(TUN_NAME) != 0) return -1;
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode)) goto fail;
    struct ifreq req = {0};
    memcpy(req.ifr_name, TUN_NAME, sizeof(TUN_NAME));
    // Exclusive allocation; never attach to an existing interface or
    // enable persistence. The last descriptor close retires the device.
    req.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
    if (ioctl(fd, TUNSETIFF, &req) != 0) goto fail;
    if (strncmp(req.ifr_name, TUN_NAME, IFNAMSIZ) != 0 ||
        if_nametoindex(TUN_NAME) == 0) goto fail;
    memset(&req, 0, sizeof(req));
    if (ioctl(fd, TUNGETIFF, &req) != 0 ||
        strncmp(req.ifr_name, TUN_NAME, IFNAMSIZ) != 0 ||
        (req.ifr_flags & (IFF_TUN | IFF_NO_PI)) != (IFF_TUN | IFF_NO_PI)) goto fail;
    // Remain DOWN. No sysctl writes, address, route, link-up or forwarding.
    // A future independently guarded setup must configure this exact TUN.
    return fd;
fail:
    close(fd);
    return -1;
}

static int transfer(int socket_fd, int tun_fd) {
    char marker = 'T';
    struct iovec iov = { .iov_base = &marker, .iov_len = 1 };
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
    if (!header) return 0;
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &tun_fd, sizeof(tun_fd));
    // Nonblocking one-shot send. No indefinite wait, no duplicate delivery.
    return sendmsg(socket_fd, &msg, MSG_NOSIGNAL) == 1;
}

int dppass_hotspot_tun_send(const char *path, uid_t uid, pid_t pid) {
    if (getuid() != 0 || geteuid() != 0 || uid < 10000 || pid <= 1 ||
        !dppass_hotspot_tun_socket_path(path)) return 0;
    int channel = connect_owner(path, uid, pid);
    if (channel < 0) return 0;
    int tun = create_tun();
    if (tun < 0) {
        close(channel);
        return 0;
    }
    int sent = transfer(channel, tun);
    // No retries of numeric fd close. Failure remains ambiguous to caller.
    int closed = close(tun) == 0;
    close(channel);
    return sent && closed;
}
