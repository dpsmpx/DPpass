//go:build linux || windows

package bridge

import "testing"

// Хуки, добавленные запуском, снимаются, а прежние и старый массив — нет
// (D-97, platform_windows.go).
func TestTrimHooksDropsOnlyAddedAndKeepsOldArray(t *testing.T) {
	old := make([]int, 2, 8)
	old[0], old[1] = 10, 11
	grown := append(old, 20, 21)
	got := trimHooks(grown, 2)
	if len(got) != 2 || got[0] != 10 || got[1] != 11 {
		t.Fatalf("после снятия %v, ждали [10 11]", got)
	}
	// Читатель со старым срезом видит добавленные хуки нетронутыми.
	if grown[2] != 20 || grown[3] != 21 {
		t.Fatalf("старый массив затёрт: %v", grown)
	}
	// Следующий запуск дописывает в новый массив, а не поверх старого.
	_ = append(got, 30)
	if grown[2] != 20 {
		t.Fatalf("новый хук записан в старый массив: %v", grown)
	}
	if same := trimHooks(grown, -1); len(same) != 4 {
		t.Fatalf("без метки список меняться не должен: %v", same)
	}
	if same := trimHooks(old, 5); len(same) != 2 {
		t.Fatalf("хуков не прибавилось — список прежний: %v", same)
	}
}
