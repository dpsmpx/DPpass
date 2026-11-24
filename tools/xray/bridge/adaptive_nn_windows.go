//go:build windows

package bridge

import "errors"

// Android-only optional model. Desktop keeps deterministic behavior.
func DPTSGeneration() int64 { return -1 }

func TrainZapret2NeuralFromDPTS(network, methods string, generation int64) error {
    return errors.New("DPTS neural training requires Android/Linux protected bridge")
}

func ConfigureZapret2NeuralModel(raw []byte) error {
    if len(raw) == 0 { return nil }
    return errors.New("Zapret2 local neural model is not supported on Windows")
}
