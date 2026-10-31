//go:build windows

package bridge

import "golang.org/x/sys/windows/registry"

// Тема приложений Windows (D-97): «Тема системы» в окне DPpass — параметр
// пользователя AppsUseLightTheme (0 — тёмная, 1 — светлая). Признаков GTK и
// KDE, по которым тему узнаёт оболочка Linux, на Windows нет.

const personalizeKey = `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`

// AppsUseLightTheme — светлая ли тема приложений; ok=false — параметра нет
// (Windows старше 10 или Wine): тему выбирает оболочка сама.
func AppsUseLightTheme() (light bool, ok bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, personalizeKey, registry.QUERY_VALUE)
	if err != nil {
		return false, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false, false
	}
	return v != 0, true
}
