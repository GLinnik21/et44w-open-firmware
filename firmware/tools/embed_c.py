#!/usr/bin/env python3
"""Embed a file as a C byte array: embed_c.py <in> <out.h> <Name> -> const char k<Name>[], k<Name>Len."""
import sys

src, out, name = sys.argv[1:4]
data = open(src, "rb").read()
lines = [", ".join(str(b) for b in data[i:i + 24]) for i in range(0, len(data), 24)]
with open(out, "w") as f:
    f.write(f"// Generated from {src} by tools/embed_c.py. Do not edit.\n#include <stddef.h>\n")
    f.write(f"static const char k{name}[] = {{\n    " + ",\n    ".join(lines) + "\n};\n")
    f.write(f"static const size_t k{name}Len = sizeof k{name};\n")
