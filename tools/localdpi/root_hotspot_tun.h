#ifndef DPPASS_ROOT_HOTSPOT_TUN_H
#define DPPASS_ROOT_HOTSPOT_TUN_H

#include <sys/types.h>

/* One nonpersistent, unaddressed TUN for a verified app-owned socket.
 * Caller must hold the exact ROOT hotspot claim. No routes/firewall. */
/* Positive interface index on confirmed transfer; zero otherwise. */
unsigned int dppass_hotspot_tun_send(const char *path, uid_t uid, pid_t pid);
int dppass_hotspot_tun_socket_path(const char *path);

#endif
