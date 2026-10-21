package com.dpsmpx.dppass.desktop

import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Запуск с правами (D-74, T17): скрипты пакета, действие polkit, PKGBUILD и
 * ярлык согласованы, а `dppass-launch` даёт процессу окна одну
 * `CAP_NET_ADMIN` от имени пользователя. Выполнение под root —
 * `tools/desktop/netns_check.py`; здесь — то, что видно без прав.
 */
class DesktopLaunchTest {
    private val pkg = File(System.getProperty("dppass.repoRoot"), "desktop/package")
    private fun text(name: String) = File(pkg, name).readText()

    /** Строки кода скрипта — без комментариев. */
    private fun code(name: String) = text(name).lines().filterNot { it.trimStart().startsWith("#") }.joinToString("\n")

    @Test
    fun launcherDropsToUserWithOnlyNetAdmin() {
        val c = code("dppass-launch")
        assertTrue(text("dppass-launch").startsWith("#!/bin/sh\n"))
        assertTrue("set -eu" in c)
        // PATH — свой: команды root не ищутся в PATH вызвавшего.
        assertTrue("PATH=/usr/bin:/bin" in c)
        // Пользователь — из PKEXEC_UID, только числом и не root.
        assertTrue("'' | *[!0-9]*) die" in c, "PKEXEC_UID — только число")
        assertTrue("[ \"\$uid\" -ne 0 ] || die" in c, "от root — отказ")
        assertTrue("getent passwd \"\$uid\"" in c)
        val exec = c.substringAfter("exec /usr/bin/setpriv ").replace("\\\n", " ")
        for (flag in listOf(
            "--reuid=\"\$uid\"", "--regid=\"\$gid\"", "--init-groups",
            "--inh-caps=-all,+net_admin", "--ambient-caps=-all,+net_admin", "--bounding-set=-all,+net_admin",
            "--no-new-privs", "--reset-env",
        )) {
            assertTrue(flag in exec, "setpriv без $flag")
        }
        assertTrue(exec.trimEnd().endsWith("/usr/bin/env \"\$@\" /usr/lib/dppass/bin/dppass-desktop"), exec)
        assertTrue("umask 077" in c, "файлы данных — только владельцу (T7)")
        // Ничего не исполняется из аргументов и окружения вызвавшего.
        assertFalse("eval" in c)
        assertFalse(Regex("""\$\{?(HOME|XDG_|JAVA_HOME|LD_|_JAVA_)""").containsMatchIn(c), "окружение вызвавшего в скрипте root")
    }

    @Test
    fun windowVariablesAreValidated() {
        val c = code("dppass-launch")
        // DISPLAY — только локальный, WAYLAND_DISPLAY — без пути, XAUTHORITY — в каталоге сеанса.
        assertTrue(":[0-9] | :[0-9][0-9] | :[0-9].[0-9] | :[0-9][0-9].[0-9]) ;;" in c)
        assertTrue("'' | *[!A-Za-z0-9._-]*) wayland= ;;" in c)
        assertTrue("*..*) xauth= ;;" in c)
        assertTrue("\"\$runtime\"/* | \"\$home\"/.Xauthority) ;;" in c)
        // Рабочий стол — только имена через «:»; иначе отбрасывается.
        assertTrue("*[!A-Za-z0-9:._-]*) desktop= ;;" in c)
    }

    /**
     * Окно Java под Wayland без перерамливающего менеджера (Hyprland, sway) —
     * серое без `_JAVA_AWT_WM_NONREPARENTING`. Ставит её скрипт root, а не
     * окружение вызвавшего: переменная — только `=1`, решение — по проверенным
     * аргументам. Как это работает на деле — `tools/desktop/netns_check.py`.
     */
    @Test
    fun nonReparentingWindowManagersGetTheJavaVariable() {
        val c = code("dppass-launch")
        assertTrue("if [ -n \"\$nonreparenting\" ]; then\n    nonreparenting=1\nelif [ -n \"\$wayland\" ]; then" in c, c)
        assertTrue("*:KDE:* | *:GNOME:* | *:X-Cinnamon:*) ;;\n    *) nonreparenting=1 ;;" in c)
        assertTrue("if [ -n \"\$nonreparenting\" ]; then set -- \"\$@\" _JAVA_AWT_WM_NONREPARENTING=1; fi" in c)
        assertTrue("if [ -n \"\$desktop\" ]; then set -- \"\$@\" XDG_CURRENT_DESKTOP=\"\$desktop\"; fi" in c)
    }

    @Test
    fun userCommandAndPolicyPointAtTheInstalledLauncher() {
        val launcher = "/usr/lib/dppass/dppass-launch"
        assertTrue(
            code("dppass").trim().endsWith(
                "exec /usr/bin/pkexec $launcher \"\${DISPLAY-}\" \"\${WAYLAND_DISPLAY-}\" \"\${XAUTHORITY-}\" \\\n" +
                    "    \"\${XDG_CURRENT_DESKTOP-}\" \"\${_JAVA_AWT_WM_NONREPARENTING-}\"",
            ),
        )
        val policy = text("com.dpsmpx.dppass.policy")
        assertTrue("<action id=\"com.dpsmpx.dppass.launch\">" in policy)
        assertTrue("<annotate key=\"org.freedesktop.policykit.exec.path\">$launcher</annotate>" in policy)
        // Только в активном локальном сеансе.
        assertTrue("<allow_any>no</allow_any>" in policy)
        assertTrue("<allow_inactive>no</allow_inactive>" in policy)
        assertTrue("<allow_active>auth_admin_keep</allow_active>" in policy)
        val pkgbuild = text("PKGBUILD.in")
        assertTrue("install -Dm755 package/dppass-launch \"\$pkgdir$launcher\"" in pkgbuild)
        assertTrue("install -Dm755 package/dppass \"\$pkgdir/usr/bin/dppass\"" in pkgbuild)
        assertTrue("\"\$pkgdir/usr/share/polkit-1/actions/com.dpsmpx.dppass.policy\"" in pkgbuild)
        assertTrue("Exec=dppass\n" in text("dppass.desktop"))
    }

    @Test
    fun scriptsParseAndAreExecutable() {
        for (name in listOf("dppass", "dppass-launch")) {
            val f = File(pkg, name)
            assertTrue(f.canExecute(), "$name без права исполнения")
            val p = ProcessBuilder("sh", "-n", f.path).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            assertTrue(p.waitFor(10, TimeUnit.SECONDS))
            assertEquals(0, p.exitValue(), "$name: sh -n: $out")
        }
    }
}
