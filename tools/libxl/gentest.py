#!/usr/bin/python

import sys
import re
import random

import libxltypes
def randomize_char(c):
    if random.random() < 0.5:
        return str.lower(c)
    else:
        return str.upper(c)

def randomize_case(s):
    r = [randomize_char(c) for c in s]
    return "".join(r)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print >>sys.stderr, "Usage: gentest.py <idl> <implementation>"
        sys.exit(1)

    random.seed()
    
    idl = sys.argv[1]
    (_,types) = libxltypes.parse(idl)
                    
    impl = sys.argv[2]
    f = open(impl, "w")
    f.write("""
#include <stdio.h>
#include \"libxl.h\"

int main(int argc, char **argv)
{
""")

    for ty in [t for t in types if isinstance(t,libxltypes.Enumeration)]:
        f.write("    %s %s_val;\n" % (ty.typename, ty.typename))
    f.write("    int rc;\n")
    f.write("\n")
                
    for ty in [t for t in types if isinstance(t,libxltypes.Enumeration)]:
        f.write("    printf(\"%s -- to string:\\n\");\n" % (ty.typename))
        for v in ty.values:
            f.write("    printf(\"\\t%s = %%d = \\\"%%s\\\"\\n\", %s, %s_to_string(%s));\n" %\
                    (v.valuename, v.name, ty.typename, v.name))
        f.write("\n")

        f.write("    printf(\"%s -- from string:\\n\");\n" % (ty.typename))
        for v in [v.valuename for v in ty.values] + ["AN INVALID VALUE"]:
            n = randomize_case(v)
            f.write("    %s_val = -1;\n" % (ty.typename))
            f.write("    rc = %s_from_string(\"%s\", &%s_val);\n" %\
                    (ty.typename, n, ty.typename))
                    
            f.write("    printf(\"\\t%s = \\\"%%s\\\" = %%d (rc %%d)\\n\", \"%s\", %s_val, rc);\n" %\
                    (v, n, ty.typename))
        f.write("\n")

    f.write("""return 0;
}
""")
