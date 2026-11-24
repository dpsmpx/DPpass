//go:build windows

package bridge

// Passive TCP_INFO is not available in this bridge on Windows.
func PassiveQuality() (int64, int64) { return -1, -1 }
