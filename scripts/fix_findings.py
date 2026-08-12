#!/usr/bin/env python3
"""Fix the malformed Sprintf in internal/vulnerability/findings/findings.go."""
PATH = "internal/vulnerability/findings/findings.go"

with open(PATH) as f:
    s = f.read()

n = s.count('"%s reported for %s. "++')
s = s.replace('"%s reported for %s. "++', '"%s reported for %s. "')
print(f"replaced {n} artifact(s)")

with open(PATH, "w") as f:
    f.write(s)
