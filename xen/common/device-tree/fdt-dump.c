/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Dump a flattened device tree blob in a DTS-like format.
 *
 * is_printable_string() and print_value() are derived from
 * util_is_printable_string() and utilfdt_print_data() in the device tree
 * compiler (dtc).
 *
 * Copyright 2011 The Chromium Authors, All Rights Reserved.
 * Copyright 2008 Jon Loeliger, Freescale Semiconductor, Inc.
 * util_is_printable_string contributed by
 *      Pantelis Antoniou <pantelis.antoniou AT gmail.com>
 */

#include <xen/bootfdt.h>
#include <xen/ctype.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/types.h>

/* Deeper nodes are still printed, but not indented any further. */
#define DUMP_MAX_INDENT_DEPTH 32

/* Spaces per nesting level. */
#define DUMP_INDENT_WIDTH 4

/* Indentation, in characters, of a node at depth @depth. */
static int __init indent_of(int depth)
{
    return DUMP_INDENT_WIDTH * min(depth, DUMP_MAX_INDENT_DEPTH);
}

static bool __init is_printable_string(const void *data, unsigned int len)
{
    const char *s = data;
    const char *se = s + len;

    /* A zero length property, or one which isn't NUL terminated, isn't one. */
    if ( (len == 0) || (s[len - 1] != '\0') )
        return false;

    while ( s < se )
    {
        const char *ss = s;

        /*
         * Xen's isprint() also accepts the characters 0xa0-0xff, while the
         * one dtc uses only accepts ASCII ones.
         */
        while ( (s < se) && *s && isascii(*s) && isprint(*s) )
            s++;

        /* Stopped on a non printable character, or the string is empty. */
        if ( (*s != '\0') || (s == ss) )
            return false;

        s++;
    }

    return true;
}

/*
 * Print the value of a property, using the same heuristics as dtc: a list of
 * NUL terminated printable strings is printed as such, a value which is a
 * multiple of 4 bytes as a list of cells, anything else as a byte string.
 *
 * The caller has already started the line (and with it selected the log
 * level), so no XENLOG_* prefix may be used here.
 */
static void __init print_value(const void *data, unsigned int len)
{
    unsigned int i;

    /* Empty property, nothing to print. */
    if ( len == 0 )
        return;

    if ( is_printable_string(data, len) )
    {
        const char *s = data;
        const char *end = data + len;

        printk(" = ");
        while ( s < end )
        {
            printk("\"%s\"", s);
            s += strlen(s) + 1;
            if ( s < end )
                printk(", ");
        }
    }
    else if ( IS_ALIGNED(len, sizeof(fdt32_t)) )
    {
        const fdt32_t *cell = data;

        printk(" = <");
        for ( i = 0; i < len / sizeof(*cell); i++ )
            printk("%s0x%08x", i ? " " : "", fdt32_ld(&cell[i]));
        printk(">");
    }
    else
    {
        const uint8_t *byte = data;

        printk(" = [");
        for ( i = 0; i < len; i++ )
            printk("%s%02x", i ? " " : "", byte[i]);
        printk("]");
    }
}

static void __init print_properties(const void *fdt, int node, int indent)
{
    int prop;

    fdt_for_each_property_offset ( prop, fdt, node )
    {
        const char *name;
        const void *data;
        int len;

        data = fdt_getprop_by_offset(fdt, prop, &name, &len);
        if ( !data )
        {
            printk(XENLOG_DEBUG "%*scouldn't read property at offset %d: %s\n",
                   indent, "", prop, fdt_strerror(len));
            return;
        }

        printk(XENLOG_DEBUG "%*s%s", indent, "", name);
        print_value(data, len);
        printk(";\n");
    }

    if ( (prop < 0) && (prop != -FDT_ERR_NOTFOUND) )
        printk(XENLOG_DEBUG "%*scouldn't walk the properties: %s\n",
               indent, "", fdt_strerror(prop));
}

void __init device_tree_dump(const struct domain *d, const void *fdt)
{
    int node, depth = 0;
    /* Depth up to which nodes are open and still have to be closed. */
    int open_depth = 0;

    printk(XENLOG_DEBUG "Device tree for %pd:\n", d);
    printk(XENLOG_DEBUG "/dts-v1/;\n");

    /*
     * fdt_next_node() signals the end of the subtree it was started on by
     * making the depth negative, and only returns an error when the blob
     * itself is malformed.
     */
    for ( node = 0; (node >= 0) && (depth >= 0);
          node = fdt_next_node(fdt, node, &depth) )
    {
        const char *name = fdt_get_name(fdt, node, NULL);

        /* Close the nodes which aren't a parent of the current one. */
        while ( open_depth > depth )
            printk(XENLOG_DEBUG "%*s};\n", indent_of(--open_depth), "");

        printk(XENLOG_DEBUG "%*s%s {\n", indent_of(depth), "",
               (depth == 0) ? "/" : (name ?: "<unknown>"));
        print_properties(fdt, node, indent_of(depth) + DUMP_INDENT_WIDTH);

        open_depth = depth + 1;
    }

    while ( open_depth > 0 )
        printk(XENLOG_DEBUG "%*s};\n", indent_of(--open_depth), "");

    if ( node < 0 )
        printk(XENLOG_DEBUG "The device tree dump is incomplete: %s\n",
               fdt_strerror(node));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
