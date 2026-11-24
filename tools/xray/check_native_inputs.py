#!/usr/bin/env python3
"""Guard native build cache inputs, before compiling the expensive APK."""
from pathlib import Path
import native

root = Path(native.PROJ)
for project in ("app", "desktop"):
    text = (root / project / "build.gradle.kts").read_text(encoding="utf-8")
    start = text.index('description = "libdppassxray.so')
    end = text.index('exclude("**/*_test.go")', start)
    inputs = text[start:end]
    for pkg in sorted(native.LIBRARY_PACKAGES):
        if f'"{pkg}/**/*.go"' not in inputs and f'"{pkg}/*.go"' not in inputs:
            raise SystemExit(f"{project}: native cache inputs missing {pkg}")
app = (root / "app/build.gradle.kts").read_text(encoding="utf-8")
for pkg in ("zapret2", "localdpi", "cmd/zapret2-alpine"):
    if f'fileTree("tools/xray/{pkg}")' not in app:
        raise SystemExit(f"Alpine planner cache inputs missing {pkg}")
print("Native Gradle input coverage: OK")
