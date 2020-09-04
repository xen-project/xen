#!/usr/bin/env python

import re,sys

pats = [
 [ r"__InClUdE__(.*)", r"#include\1" ],
 [ r"__IfDeF__ (XEN_HAVE.*)", r"#ifdef \1" ],
 [ r"__ElSe__", r"#else" ],
 [ r"__EnDif__", r"#endif" ],
 [ r"__DeFiNe__", r"#define" ],
 [ r"__UnDeF__", r"#undef" ],
 [ r"\"xen-compat.h\"", r"<public/xen-compat.h>" ],
 [ r"(struct|union|enum)\s+(xen_?)?(\w)", r"\1 compat_\3" ],
 [ r"typedef(.*)@KeeP@((xen_?)?)([\w]+)([^\w])",
   r"typedef\1\2\4 __attribute__((__aligned__(__alignof(\1compat_\4))))\5" ],
 [ r"_t([^\w]|$)", r"_compat_t\1" ],
 [ r"int(8|16|32|64_aligned)_compat_t([^\w]|$)", r"int\1_t\2" ],
 [ r"(\su?int64(_compat)?)_T([^\w]|$)", r"\1_t\3" ],
 [ r"(^|[^\w])xen_?(\w*)_compat_t([^\w]|$$)", r"\1compat_\2_t\3" ],
 [ r"(^|[^\w])XEN_?", r"\1COMPAT_" ],
 [ r"(^|[^\w])Xen_?", r"\1Compat_" ],
 [ r"(^|[^\w])COMPAT_HANDLE_64\(", r"\1XEN_GUEST_HANDLE_64(" ],
 [ r"(^|[^\w])long([^\w]|$$)", r"\1int\2" ]
];

for line in sys.stdin.readlines():
    for pat in pats:
        line = re.subn(pat[0], pat[1], line)[0]
    print(line.rstrip())
