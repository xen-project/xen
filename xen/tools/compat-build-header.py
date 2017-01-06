#!/usr/bin/env python

import re,sys

pats = [
 [ r"__InClUdE__(.*)", r"#include\1\n#pragma pack(4)" ],
 [ r"__IfDeF__ (XEN_HAVE.*)", r"#ifdef \1" ],
 [ r"__ElSe__", r"#else" ],
 [ r"__EnDif__", r"#endif" ],
 [ r"__DeFiNe__", r"#define" ],
 [ r"__UnDeF__", r"#undef" ],
 [ r"\"xen-compat.h\"", r"<public/xen-compat.h>" ],
 [ r"(struct|union|enum)\s+(xen_?)?(\w)", r"\1 compat_\3" ],
 [ r"@KeeP@", r"" ],
 [ r"_t([^\w]|$)", r"_compat_t\1" ],
 [ r"(8|16|32|64)_compat_t([^\w]|$)", r"\1_t\2" ],
 [ r"(^|[^\w])xen_?(\w*)_compat_t([^\w]|$$)", r"\1compat_\2_t\3" ],
 [ r"(^|[^\w])XEN_?", r"\1COMPAT_" ],
 [ r"(^|[^\w])Xen_?", r"\1Compat_" ],
 [ r"(^|[^\w])long([^\w]|$$)", r"\1int\2" ]
];

for line in sys.stdin.readlines():
    for pat in pats:
        line = re.subn(pat[0], pat[1], line)[0]
    print line.rstrip()
