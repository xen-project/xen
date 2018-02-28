#!/usr/bin/env python

import re,sys

pats = [
 [ r"^\s*#\s*include\s+", r"__InClUdE__ " ],
 [ r"^\s*#\s*ifdef (XEN_HAVE.*)\s+", r"__IfDeF__ \1" ],
 [ r"^\s*#\s*else /\* (XEN_HAVE.*) \*/\s+", r"__ElSe__" ],
 [ r"^\s*#\s*endif /\* (XEN_HAVE.*) \*/\s+", r"__EnDif__" ],
 [ r"^\s*#\s*define\s+([A-Z_]*_GUEST_HANDLE)", r"#define HIDE_\1" ],
 [ r"^\s*#\s*define\s+([a-z_]*_guest_handle)", r"#define hide_\1" ],
 [ r"XEN_GUEST_HANDLE(_[0-9A-Fa-f]+)?", r"COMPAT_HANDLE" ],
];

xlatf = open('xlat.lst', 'r')
for line in xlatf.readlines():
    match = re.subn(r"^\s*\?\s+(\w*)\s.*", r"\1", line.rstrip())
    if match[1]:
        pats.append([ r"(struct|union)\s+(%s|xen_%s)\s+(\w)" % (match[0], match[0]),
                      r"\1 @KeeP@\2 \3" ])
xlatf.close()

for pat in pats:
    pat[0] = re.compile(pat[0])

for line in sys.stdin.readlines():
    for pat in pats:
        line = re.sub(pat[0], pat[1], line)
    print(line.rstrip())
