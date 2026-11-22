//go:build windows

package bridge

// Windows builds share the JNI ABI but do not have the Linux-only
// experimental protected-socket interceptor. Return zeros rather than
// linking missing Linux symbols; only the Android Zapret2 mode logs stages.
func Zapret2Stages() [15]int64 { return [15]int64{} }
