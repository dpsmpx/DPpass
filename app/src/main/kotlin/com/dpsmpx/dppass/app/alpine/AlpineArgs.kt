package com.dpsmpx.dppass.app.alpine

/**
 * Minimal, independently testable PRoot adapter derived from DPmetaApp
 * dpai/execution/linux/ProotHost.kt. PRoot's "-0" fakes uid=0 only inside
 * the guest; no CAP_NET_ADMIN, NFQUEUE, or Android root is obtained.
 */
internal object AlpineArgs {
    data class Layout(val proot: String, val loader: String, val rootfs: String, val tmp: String)

    private val devices = listOf(
        "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
        "/dev/tty", "/dev/ptmx", "/dev/pts",
    )

    fun shell(layout: Layout): List<String> = command(layout, listOf("/bin/sh", "-l"))

    fun command(layout: Layout, guestArgv: List<String>): List<String> {
        require(guestArgv.isNotEmpty()) { "guest program missing" }
        val apk = guestArgv.first().substringAfterLast('/') == "apk"
        return buildList {
            add(layout.proot)
            add("--kill-on-exit")
            add("--link2symlink")
            add("-0")
            add("-r")
            add(layout.rootfs)
            devices.forEach { add("-b"); add(it) }
            // apk-tools on Android cannot hardlink O_TMPFILE via /proc/self/fd.
            if (!apk) {
                add("-b"); add("/proc")
                listOf(
                    "/proc/self/fd:/dev/fd",
                    "/proc/self/fd/0:/dev/stdin",
                    "/proc/self/fd/1:/dev/stdout",
                    "/proc/self/fd/2:/dev/stderr",
                ).forEach { add("-b"); add(it) }
            }
            add("-w"); add("/root")
            addAll(guestArgv)
        }
    }

    /** Never pass the Android app's environment, secrets, or inherited PATH. */
    fun environment(layout: Layout): Map<String, String> = mapOf(
        "PROOT_LOADER" to layout.loader,
        "PROOT_TMP_DIR" to layout.tmp,
        "HOME" to "/root",
        "PATH" to "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG" to "C.UTF-8",
        "TERM" to "dumb",
        "TMPDIR" to "/tmp",
    )
}
