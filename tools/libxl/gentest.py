#!/usr/bin/python

import os
import sys
import re
import random

import idl

def randomize_char(c):
    if random.random() < 0.5:
        return str.lower(c)
    else:
        return str.upper(c)

def randomize_case(s):
    r = [randomize_char(c) for c in s]
    return "".join(r)

def randomize_enum(e):
    return random.choice([v.name for v in e.values])

handcoded = ["libxl_bitmap", "libxl_key_value_list",
             "libxl_cpuid_policy_list", "libxl_string_list"]

def gen_rand_init(ty, v, indent = "    ", parent = None):
    s = ""
    if isinstance(ty, idl.Enumeration):
        s += "%s = %s;\n" % (ty.pass_arg(v, parent is None), randomize_enum(ty))
    elif isinstance(ty, idl.Array):
        if parent is None:
            raise Exception("Array type must have a parent")
        s += "%s = test_rand(8);\n" % (parent + ty.lenvar.name)
        s += "%s = calloc(%s, sizeof(*%s));\n" % \
            (v, parent + ty.lenvar.name, v)
        s += "assert(%s);\n" % (v, )
        s += "{\n"
        s += "    int i;\n"
        s += "    for (i=0; i<%s; i++)\n" % (parent + ty.lenvar.name)
        s += gen_rand_init(ty.elem_type, v+"[i]",
                           indent + "        ", parent)
        s += "}\n"
    elif isinstance(ty, idl.KeyedUnion):
        if parent is None:
            raise Exception("KeyedUnion type must have a parent")
        s += gen_rand_init(ty.keyvar.type, parent + ty.keyvar.name, indent, parent)
        s += "switch (%s) {\n" % (parent + ty.keyvar.name)
        for f in ty.fields:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            s += "case %s:\n" % f.enumname
            if f.type is not None:
                s += gen_rand_init(f.type, fexpr, indent + "    ", nparent)
            s += "    break;\n"
        s += "}\n"
    elif isinstance(ty, idl.Struct) \
     and (parent is None or ty.json_gen_fn is None):
        for f in [f for f in ty.fields if not f.const]:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            s += gen_rand_init(f.type, fexpr, "", nparent)
    elif hasattr(ty, "rand_init") and ty.rand_init is not None:
        s += "%s(%s);\n" % (ty.rand_init,
                            ty.pass_arg(v, isref=parent is None,
                                        passby=idl.PASS_BY_REFERENCE))
    elif ty.typename in ["libxl_uuid", "libxl_mac", "libxl_hwcap", "libxl_ms_vm_genid"]:
        s += "rand_bytes((uint8_t *)%s, sizeof(*%s));\n" % (v,v)
    elif ty.typename in ["libxl_domid", "libxl_devid"] or isinstance(ty, idl.Number):
        s += "%s = test_rand(sizeof(%s) * 8);\n" % \
             (ty.pass_arg(v, parent is None),
              ty.pass_arg(v, parent is None))
    elif ty.typename in ["bool"]:
        s += "%s = test_rand(2);\n" % v
    elif ty.typename in ["libxl_defbool"]:
        s += "libxl_defbool_set(%s, test_rand(2));\n" % v
    elif ty.typename in ["char *"]:
        s += "%s = rand_str();\n" % v
    elif ty.private:
        pass
    elif ty.typename in handcoded:
        raise Exception("Gen for handcoded %s" % ty.typename)
    else:
        raise Exception("Cannot randomly init %s" % ty.typename)

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print >>sys.stderr, "Usage: gentest.py <idl> <implementation>"
        sys.exit(1)

    random.seed(os.getenv('LIBXL_TESTIDL_SEED'))

    (builtins,types) = idl.parse(sys.argv[1])

    impl = sys.argv[2]
    f = open(impl, "w")
    f.write("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "libxl.h"
#include "libxl_utils.h"

static int test_rand(unsigned max)
{
    /* We are not using rand() for its cryptographic properies. */
    return rand() % max;
}

static char *rand_str(void)
{
    int i, sz = test_rand(32);
    char *s = malloc(sz+1);
    assert(s);
    for (i=0; i<sz; i++)
        s[i] = 'a' + test_rand(26);
    s[i] = '\\0';
    return s;
}

static void rand_bytes(uint8_t *p, size_t sz)
{
    int i;
    for (i=0; i<sz; i++)
        p[i] = test_rand(256);
}

static void libxl_bitmap_rand_init(libxl_bitmap *bitmap)
{
    int i;
    bitmap->size = test_rand(16);
    bitmap->map = calloc(bitmap->size, sizeof(*bitmap->map));
    assert(bitmap->map);
    libxl_for_each_bit(i, *bitmap) {
        if (test_rand(2))
            libxl_bitmap_set(bitmap, i);
        else
            libxl_bitmap_reset(bitmap, i);
    }
}

static void libxl_key_value_list_rand_init(libxl_key_value_list *pkvl)
{
    int i, nr_kvp = test_rand(16);
    libxl_key_value_list kvl = calloc(nr_kvp+1, 2*sizeof(char *));
    assert(kvl);

    for (i = 0; i<2*nr_kvp; i += 2) {
        kvl[i] = rand_str();
        if (test_rand(8))
            kvl[i+1] = rand_str();
        else
            kvl[i+1] = NULL;
    }
    kvl[i] = NULL;
    kvl[i+1] = NULL;
    *pkvl = kvl;
}

static void libxl_cpuid_policy_list_rand_init(libxl_cpuid_policy_list *pp)
{
    int i, nr_policies = test_rand(16);
    struct {
        const char *n;
        int w;
    } options[] = {
      /* A random selection from libxl_cpuid_parse_config */
        {"maxleaf",     32},
        {"family",       8},
        {"model",        8},
        {"stepping",     4},
        {"localapicid",  8},
        {"proccount",    8},
        {"clflush",      8},
        {"brandid",      8},
        {"f16c",         1},
        {"avx",          1},
        {"osxsave",      1},
        {"xsave",        1},
        {"aes",          1},
        {"popcnt",       1},
        {"movbe",        1},
        {"x2apic",       1},
        {"sse4.2",       1},
        {"sse4.1",       1},
        {"dca",          1},
        {"pdcm",         1},
        {"procpkg",      6},
    };
    const int nr_options = sizeof(options)/sizeof(options[0]);
    char buf[64];
    libxl_cpuid_policy_list p = NULL;

    for (i = 0; i < nr_policies; i++) {
        int opt = test_rand(nr_options);
        int val = test_rand(1<<options[opt].w);
        snprintf(buf, 64, \"%s=%#x\", options[opt].n, val);
        libxl_cpuid_parse_config(&p, buf);
    }
    *pp = p;
}

static void libxl_string_list_rand_init(libxl_string_list *p)
{
    int i, nr = test_rand(16);
    libxl_string_list l = calloc(nr+1, sizeof(char *));
    assert(l);

    for (i = 0; i<nr; i++) {
        l[i] = rand_str();
    }
    l[i] = NULL;
    *p = l;
}
""")
    for ty in builtins + types:
        if isinstance(ty, idl.Number): continue
        if ty.typename not in handcoded:
            f.write("static void %s_rand_init(%s);\n" % \
                    (ty.typename,
                     ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
            f.write("static void %s_rand_init(%s)\n" % \
                    (ty.typename,
                     ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
            f.write("{\n")
            f.write(gen_rand_init(ty, "p"))
            f.write("}\n")
            f.write("\n")
        ty.rand_init = "%s_rand_init" % ty.typename

    f.write("""
int main(int argc, char **argv)
{
""")

    for ty in types:
        f.write("    %s %s_val, %s_val_new;\n" % \
                (ty.typename, ty.typename, ty.typename))
    f.write("""
    int rc;
    char *s, *new_s, *json_string;
    xentoollog_logger_stdiostream *logger;
    libxl_ctx *ctx;

    logger = xtl_createlogger_stdiostream(stderr, XTL_DETAIL, 0);
    if (!logger) exit(1);

    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, (xentoollog_logger*)logger)) {
        fprintf(stderr, "cannot init xl context\\n");
        exit(1);
    }
""")
    f.write("    printf(\"Testing TYPE_to/from_json()\\n\");\n")
    f.write("    printf(\"----------------------\\n\");\n")
    f.write("    printf(\"\\n\");\n")
    for ty in [t for t in types if t.json_gen_fn is not None]:
        arg = ty.typename + "_val"
        f.write("    %s_rand_init(%s);\n" % (ty.typename, \
            ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE)))
        if not isinstance(ty, idl.Enumeration):
            iters = random.randrange(1,10)
            while iters > 0:
                f.write("    %s_init(%s_new);\n" % (ty.typename, \
                    ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE)))
                iters -= 1
        f.write("    s = %s_to_json(ctx, %s);\n" % \
                (ty.typename, ty.pass_arg(arg, isref=False)))
        f.write("    printf(\"%%s: %%s\\n\", \"%s\", s);\n" % ty.typename)
        f.write("    if (s == NULL) abort();\n")
        f.write("    rc = %s_from_json(ctx, &%s_val_new, s);\n" % \
                (ty.typename, ty.typename))
        f.write("    if (rc) abort();\n")
        f.write("    new_s = %s_to_json(ctx, %s_new);\n" % \
                (ty.typename, ty.pass_arg(arg, isref=False)))
        f.write("    if (new_s == NULL) abort();\n")
        f.write("    if (strcmp(s, new_s)) {\n")
        f.write("        printf(\"Huh? Regenerated string different from original string.\\n\");\n")
        f.write("        printf(\"Regenerated string: %s\\n\", new_s);\n")
        f.write("        abort();\n")
        f.write("    }\n")
        f.write("    free(s);\n")
        f.write("    free(new_s);\n")
        if ty.dispose_fn is not None:
            iters = random.randrange(1,10)
            f.write("    %s(&%s_val);\n" % (ty.dispose_fn, ty.typename))
            while iters > 0:
                f.write("    %s(&%s_val_new);\n" % (ty.dispose_fn, ty.typename))
                iters -= 1
        f.write("\n")

    f.write("    printf(\"Testing TYPE_copy()\\n\");\n")
    f.write("    printf(\"----------------------\\n\");\n")
    f.write("    printf(\"\\n\");\n")
    for ty in [t for t in types if t.copy_fn is not None]:
        f.write("    printf(\"Testing %s_copy, \");\n" % ty.typename)
        arg = ty.typename + "_val"
        f.write("    %s_init(%s);\n" % (ty.typename, \
            ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE)))
        f.write("    %s_rand_init(%s);\n" % (ty.typename, \
            ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE)))
        f.write("    %s_init(%s_new);\n" % (ty.typename, \
            ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE)))
        f.write("    %s_copy(ctx, %s_new, %s);\n" % (ty.typename, \
            ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE), \
            ty.pass_arg(arg, isref=False, passby=idl.PASS_BY_REFERENCE)))
        f.write("    s = %s_to_json(ctx, %s);\n" % \
                (ty.typename, ty.pass_arg(arg, isref=False)))
        f.write("    if (s == NULL) abort();\n")
        f.write("    new_s = %s_to_json(ctx, %s_new);\n" % \
                (ty.typename, ty.pass_arg(arg, isref=False)))
        f.write("    if (new_s == NULL) abort();\n")
        f.write("    if (strcmp(s, new_s)) {\n")
        f.write("        printf(\"Huh? Deep copy for %s failed. Regenerated string different from original string.\\n\");\n" \
                % ty.typename)
        f.write("        printf(\"Original string: %s\\n\", s);\n")
        f.write("        printf(\"Regenerated string: %s\\n\", new_s);\n")
        f.write("        abort();\n")
        f.write("    }\n")
        f.write("    free(s);\n")
        f.write("    free(new_s);\n")
        if ty.dispose_fn is not None:
            f.write("    %s(&%s_val);\n" % (ty.dispose_fn, ty.typename))
            f.write("    %s(&%s_val_new);\n" % (ty.dispose_fn, ty.typename))
        f.write("    printf(\"done\\n\");\n")
        f.write("\n")

    f.write("    printf(\"\\n\");\n")
    f.write("    printf(\"Testing Enumerations\\n\");\n")
    f.write("    printf(\"--------------------\\n\");\n")
    f.write("    printf(\"\\n\");\n")
    for ty in [t for t in types if isinstance(t,idl.Enumeration)]:
        f.write("    printf(\"%s -- to string:\\n\");\n" % (ty.typename))
        for v in ty.values:
            f.write("    printf(\"\\t%s = %%d = \\\"%%s\\\"\\n\", " \
                    "%s, %s_to_string(%s));\n" % \
                    (v.valuename, v.name, ty.typename, v.name))
        f.write("\n")

        f.write("    printf(\"%s -- to JSON:\\n\");\n" % (ty.typename))
        for v in ty.values:
            f.write("    json_string = %s_to_json(ctx, %s);\n" % \
                    (ty.typename, v.name))
            f.write("    printf(\"\\t%s = %%d = %%s\", " \
                    "%s, json_string);\n" %\
                    (v.valuename, v.name))
            f.write("    free(json_string);\n");
            f.write("    json_string = NULL;\n");
        f.write("\n")

        f.write("    printf(\"%s -- from string:\\n\");\n" % (ty.typename))
        for v in [v.valuename for v in ty.values] + ["AN INVALID VALUE"]:
            n = randomize_case(v)
            f.write("    %s_val = -1;\n" % (ty.typename))
            f.write("    rc = %s_from_string(\"%s\", &%s_val);\n" %\
                    (ty.typename, n, ty.typename))

            f.write("    printf(\"\\t%s = \\\"%%s\\\" = %%d (rc %%d)\\n\", " \
                    "\"%s\", %s_val, rc);\n" %\
                    (v, n, ty.typename))
        f.write("\n")

    f.write("""

    libxl_ctx_free(ctx);
    xtl_logger_destroy((xentoollog_logger*)logger);

    return 0;
}
""")
