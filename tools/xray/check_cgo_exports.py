#!/usr/bin/env python3
"""Reject repeated blank parameter names in exported JNI functions.

Go permits repeated blank identifiers; cgo can emit duplicate C parameter
names. This early lint covers the current JNI declaration style, including
multiline parameter lists. Actual cgo compilation remains mandatory.
"""
from pathlib import Path
import re

EXPORT = re.compile(r"(?m)^//export[ \t]+(\w+)[ \t]*\r?\nfunc[ \t]+\1\s*\(([^)]*)\)")
BLANK = re.compile(r"(?:^|,)\s*_(?=\s|,)")

def violations(source):
    return [name for name, params in EXPORT.findall(source)
            if len(BLANK.findall(params)) > 1]

def main():
    assert violations("//export F\nfunc F(_ *C.JNIEnv, _ C.jclass) C.jlong {") == ["F"]
    assert violations("//export F\nfunc F(env *C.JNIEnv, _ C.jclass) C.jlong {") == []
    assert violations("//export F\nfunc F(\n _ *C.JNIEnv,\n _ C.jclass,\n) {") == ["F"]
    failures = []
    for source in sorted((Path(__file__).resolve().parent / "jni").glob("*.go")):
        failures.extend(f"{source.name}: {name}" for name in
                        violations(source.read_text(encoding="utf-8")))
    if failures:
        raise SystemExit("Duplicate blank cgo export parameters:\n" + "\n".join(failures))
    print("JNI export blank parameter check: OK")

if __name__ == "__main__":
    main()
