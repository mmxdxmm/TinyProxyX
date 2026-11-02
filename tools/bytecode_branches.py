#!/usr/bin/env python3
"""Count real conditional-branch bytecode instructions per class/method.

Parses `javap -c -p` output.  A "branch" is any if* / if_icmp* / if_acmp* /
ifnull / ifnonnull instruction plus tableswitch/lookupswitch (one indirect
jump).  Unconditional goto is not a prediction point and is excluded.

Method headers are recognised structurally (a line that starts with exactly two
spaces, is not an instruction, and is followed by a `Code:` line), so
constructors, `<clinit>` (`static {}`) and instance initialisers (`{}`) are all
attributed correctly.

Usage:
    bytecode_branches.py <classes-dir> [--no-clinit]
"""
import json
import re
import subprocess
import sys
from pathlib import Path

INSN = re.compile(r"^\s+\d+:\s+(\S+)")
HEAD = re.compile(r"^  \S.*[;}]$")


def clean_name(h):
    s = h.strip()
    if s.endswith(";"):
        s = s[:-1]
    i = s.find("(")
    if i > 0:
        j = s.rfind(" ", 0, i)
        name = s[j + 1:i]
        # constructors print as "public com.foo.Bar(...)"; keep the simple name
        if "." in name:
            name = name[name.rfind(".") + 1:]
        return name
    if s.endswith("{}"):
        return "<clinit>" if s.startswith("static") else "<init-block>"
    return s


def scan_class(path):
    out = subprocess.run(["javap", "-c", "-p", str(path)], capture_output=True, text=True).stdout
    lines = out.splitlines()
    methods = {}
    cur = None
    in_code = False
    for i, line in enumerate(lines):
        if HEAD.match(line) and i + 1 < len(lines) and lines[i + 1].strip() == "Code:":
            cur = clean_name(line)
            methods.setdefault(cur, 0)
            in_code = True
            continue
        if in_code:
            m = INSN.match(line)
            if m and (m.group(1).startswith("if") or m.group(1) in ("tableswitch", "lookupswitch")):
                methods[cur] += 1
    return methods


def main(argv):
    root = Path(argv[1] if len(argv) > 1 else ".")
    drop_clinit = "--no-clinit" in argv
    total = branchy = methods = 0
    per_class = {}
    per_method = []
    init_total = 0
    for p in sorted(root.rglob("*.class")):
        ms = scan_class(p)
        s = 0
        for name, n in ms.items():
            methods += 1
            if name in ("<clinit>", "<init-block>"):
                init_total += n
                if drop_clinit:
                    continue
            total += n
            s += n
            if n:
                branchy += 1
                per_method.append({"cls": p.name, "method": name, "branches": n})
        if s:
            per_class[str(p.relative_to(root))] = s
    print(json.dumps({
        "methods": methods,
        "branchy_methods": branchy,
        "branches": total,
        "clinit_branches": init_total,
        "per_class": per_class,
        "top": sorted(per_method, key=lambda x: -x["branches"])[:30],
    }, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main(sys.argv)
