//go:build linux || windows

package bridge

import "slices"

// trimHooks возвращает список хуков сокетов Xray без добавленных после
// mark (D-97): копию начала, а не срез того же массива — Xray читает
// список без блокировки, и читатель со старым срезом должен видеть
// прежние хуки, а не затёртые. mark < 0 или хуков не прибавилось — тот же
// список.
func trimHooks[T any](hooks []T, mark int) []T {
	if mark < 0 || len(hooks) <= mark {
		return hooks
	}
	return slices.Clone(hooks[:mark])
}
