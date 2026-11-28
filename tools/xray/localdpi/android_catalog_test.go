package localdpi

import (
    "os"
    "path/filepath"
    "reflect"
    "regexp"
    "strings"
    "testing"
)

// The Android diagnostic catalog preserves UI ordering and the wire name
// "plain" for the native pass control. Verify the actual declaration,
// not a hand-maintained copy of the current neural output set. Also check
// ordered model slots and schema prefix to catch same-width layout drift.
func TestAndroidDiagnosticCatalogParity(t *testing.T) {
    path := filepath.Join("..", "..", "..", "engine", "src", "main", "kotlin",
        "com", "dpsmpx", "dppass", "engine", "Zapret2ProbeCatalog.kt")
    source, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    readList := func(name string) []string {
        t.Helper()
        expr := regexp.MustCompile("(?s)\\bval\\s+" + name + "\\s*:\\s*List<String>\\s*=\\s*listOf\\(([^)]*)\\)")
        match := expr.FindAllStringSubmatch(string(source), -1)
        if len(match) != 1 { t.Fatalf("expected one Android declaration for %s", name) }
        token := regexp.MustCompile("\"([a-z0-9-]+)\"")
        var ids []string
        for _, item := range strings.Split(match[0][1], ",") {
            item = strings.TrimSpace(item)
            if item == "" { continue }
            m := token.FindStringSubmatch(item)
            if len(m) != 2 || m[0] != item { t.Fatalf("unexpected catalog entry %q", item) }
            ids = append(ids, m[1])
        }
        return ids
    }
    prefix := strings.SplitN(ModelFormat(), ":tcp=", 2)[0]
    if !strings.Contains(string(source), "\"" + prefix + ":tcp=\"") {
        t.Fatal("Android model schema prefix mismatch")
    }
    for _, tc := range []struct {
        name string
        kind ExecutorKind
    }{
        {"rootSocketModelFormat", RootSocket},
        {"rootPacketModelFormat", RootPacket},
    } {
        format := StrategyModelFormat(tc.kind)
        if format == ModelFormat() || !strings.HasPrefix(format, ModelFormat()) {
            t.Fatalf("invalid scoped format for %s: %q", tc.name, format)
        }
        suffix := strings.TrimPrefix(format, ModelFormat())
        declaration := tc.name + ": String = modelFormat + \"" + suffix + "\""
        if !strings.Contains(string(source), declaration) {
            t.Fatalf("Android scoped model marker mismatch: %s", tc.name)
        }
    }
    for _, tc := range []struct{name string; transport Transport}{
        {"siteTcpMethods", TLS}, {"siteQuicMethods", QUIC},
    } {
        ids := readList(tc.name)
        if len(ids) == 0 || ids[0] != "plain" { t.Fatal("missing diagnostic baseline", tc.name) }
        seen := map[string]bool{}
        for _, id := range ids {
            if id == "plain" { id = "pass" }
            if seen[id] { t.Fatal("duplicate Android method", id) }
            seen[id] = true
        }
        expected := map[string]bool{}
        for _, id := range Candidates(tc.transport) { expected[id] = true }
        if !reflect.DeepEqual(seen, expected) {
            t.Fatalf("%s: Android %v native %v", tc.name, seen, expected)
        }
        ordered := append([]string(nil), ids[1:]...)
        if tc.transport == QUIC { ordered = append(ordered, "pass") }
        if !reflect.DeepEqual(ordered, ModelMethods(tc.transport)) {
            t.Fatalf("ordered model layout mismatch: %v vs %v", ordered, ModelMethods(tc.transport))
        }
        if tc.transport == TLS {
            for _, id := range ids[1:] {
                if HTMLIndex(id) < 0 { t.Fatal("nontrainable diagnostic method", id) }
            }
            if len(ids)-1 != TCPOutputCount() { t.Fatal("incomplete HTML calibration set") }
        }
    }
}
