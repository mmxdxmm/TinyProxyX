#!/usr/bin/env python3
"""Rough Java branch/cyclomatic census used to measure the refactor delta.

Comments and literals are blanked first, then every method body is located by
brace matching and scanned for branch constructs.  Deliberately conservative:
one point per if / else-if / case / ternary / && / || / for / while / do.
"""
import json
import re
import sys
from pathlib import Path

BRANCH = re.compile(r"\b(if|else|case|for|while|do)\b|&&|\|\||\?")


def blank(text):
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                out.append(' ')
                i += 1
        elif c == '/' and i + 1 < n and text[i + 1] == '*':
            out.append('  ')
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                out.append('\n' if text[i] == '\n' else ' ')
                i += 1
            out.append('  ')
            i += 2
        elif c in '"\'':
            q = c
            out.append(' ')
            i += 1
            while i < n and text[i] != q:
                if text[i] == '\\':
                    out.append('  ')
                    i += 2
                    continue
                out.append('\n' if text[i] == '\n' else ' ')
                i += 1
            out.append(' ')
            i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


SIG = re.compile(
    r"(?m)^[ \t]*(?:@\w+(?:\([^)]*\))?[ \t]*)*"
    r"(?:(?:public|private|protected|static|final|synchronized|abstract|native|strictfp|default)\s+)*"
    r"(?:<[^>{};]+>\s+)?"
    r"([\w.$<>\[\], ?]+?)\s+(\w+)\s*\(([^;{}]*)\)\s*(?:throws\s+[^{]+)?\{"
)


def match_brace(text, start):
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text) - 1


def scan(path):
    raw = path.read_text(encoding='utf-8', errors='replace')
    clean = blank(raw)
    methods = []
    for m in SIG.finditer(clean):
        name = m.group(2)
        if name in ('if', 'for', 'while', 'switch', 'catch', 'synchronized'):
            continue
        body_start = m.end() - 1
        body_end = match_brace(clean, body_start)
        body = clean[body_start:body_end + 1]
        hits = BRANCH.findall(body)
        methods.append({
            'file': str(path),
            'name': name,
            'line': clean[:m.start()].count('\n') + 1,
            'branches': len(hits),
            'complexity': 1 + len(hits),
        })
    return methods


def main(root):
    root = Path(root)
    allm = []
    for p in sorted(root.rglob('*.java')):
        if any(part in ('.stage', 'build', '.git') for part in p.parts):
            continue
        allm.extend(scan(p))
    branchy = [m for m in allm if m['branches'] > 0]
    total_b = sum(m['branches'] for m in allm)
    total_c = sum(m['complexity'] for m in allm)
    per_file = {}
    for m in allm:
        f = per_file.setdefault(m['file'], {'methods': 0, 'branchy': 0, 'branches': 0})
        f['methods'] += 1
        f['branches'] += m['branches']
        if m['branches']:
            f['branchy'] += 1
    print(json.dumps({
        'methods': len(allm),
        'branchy_methods': len(branchy),
        'branches': total_b,
        'complexity': total_c,
        'top': sorted(branchy, key=lambda m: -m['branches'])[:25],
        'per_file': per_file,
    }, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
