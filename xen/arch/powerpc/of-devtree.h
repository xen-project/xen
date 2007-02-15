/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2005, 2006, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _OF_DEVTREE_H
#define _OF_DEVTREE_H

#include <xen/types.h>
#include <xen/string.h>
#include <xen/kernel.h>
#include <public/xen.h>

enum {
    OF_FAILURE = -1,
    OF_SUCCESS = 0,
};

union of_pci_hi {
    u32 word;
    struct {
        u32 opa_n: 1; /* relocatable */
        u32 opa_p: 1; /* prefetchable */
        u32 opa_t: 1; /* aliased */
        u32 _opa_res: 3;
        u32 opa: 2; /* space code */
        u32  opa_b: 8; /* bus number */
        u32 opa_d: 5; /* device number */
        u32 opa_f: 3; /* function number */
        u32 opa_r: 8; /* register number */
    } bits;
};

struct of_pci_addr {
    union of_pci_hi opa_hi;
    u32 opa_mid;
    u32 opa_lo;
};

struct of_pci_range32 {
    struct of_pci_addr opr_addr;
    u32 opr_phys;
    u32 opr_size;
};

struct of_pci_range64 {
    struct of_pci_addr opr_addr;
    u32 opr_phys_hi;
    u32 opr_phys_lo;
    u32 opr_size_hi;
    u32 opr_size_lo;
};

struct of_pci_addr_range64 {
    struct of_pci_addr opr_addr;
    u32 opr_size_hi;
    u32 opr_size_lo;
};

struct reg_property32 {
    u32 address;
    u32 size;
};

typedef s32 ofdn_t;

#define OFD_ROOT 1
#define OFD_DUMP_NAMES 0x1
#define OFD_DUMP_VALUES 0x2
#define OFD_DUMP_ALL (OFD_DUMP_VALUES|OFD_DUMP_NAMES)

extern void *ofd_create(void *mem, size_t sz);
extern ofdn_t ofd_node_parent(void *mem, ofdn_t n);
extern ofdn_t ofd_node_peer(void *mem, ofdn_t n);
extern ofdn_t ofd_node_child(void *mem, ofdn_t p);
extern const char *ofd_node_path(void *mem, ofdn_t p);
extern int ofd_node_to_path(void *mem, ofdn_t p, void *buf, size_t sz);
extern ofdn_t ofd_node_child_create(void *mem, ofdn_t parent,
                                    const char *path, size_t pathlen);
extern ofdn_t ofd_node_peer_create(void *mem, ofdn_t sibling,
                                   const char *path, size_t pathlen);
extern ofdn_t ofd_node_find(void *mem, const char *devspec);
extern ofdn_t ofd_node_add(void *m, ofdn_t n, const char *path, size_t sz);
extern int ofd_node_prune(void *m, ofdn_t n);
extern int ofd_prune_path(void *m, const char *path);
extern ofdn_t ofd_node_io(void *mem, ofdn_t n);

extern ofdn_t ofd_nextprop(void *mem, ofdn_t n, const char *prev, char *name);
extern ofdn_t ofd_prop_find(void *mem, ofdn_t n, const char *name);
extern int ofd_getprop(void *mem, ofdn_t n, const char *name,
                       void *buf, size_t sz);
extern int ofd_getproplen(void *mem, ofdn_t n, const char *name);

extern int ofd_setprop(void *mem, ofdn_t n, const char *name,
                       const void *buf, size_t sz);
extern void ofd_prop_remove(void *mem, ofdn_t node, ofdn_t prop);
extern ofdn_t ofd_prop_add(void *mem, ofdn_t n, const char *name,
                           const void *buf, size_t sz);
extern ofdn_t ofd_io_create(void *m, ofdn_t node, u64 open);
extern u32 ofd_io_open(void *mem, ofdn_t n);
extern void ofd_io_close(void *mem, ofdn_t n);


typedef void (*walk_fn)(void *m, const char *pre, ofdn_t p, int arg);
extern void ofd_dump_props(void *m, const char *pre, ofdn_t p, int dump);

extern void ofd_walk(void *m, const char *pre, ofdn_t p, walk_fn fn, int arg);


/* Recursively look up #address_cells and #size_cells properties */
extern int ofd_getcells(void *mem, ofdn_t n,
                        u32 *addr_cells, u32 *size_cells);

extern size_t ofd_size(void *mem);
extern size_t ofd_space(void *mem);

extern void ofd_prop_print(const char *head, const char *path,
                           const char *name, const char *prop, size_t sz);

extern ofdn_t ofd_node_find_by_prop(void *mem, ofdn_t n, const char *name,
                                    const void *val, size_t sz);
extern ofdn_t ofd_node_find_next(void *mem, ofdn_t n);
extern ofdn_t ofd_node_find_prev(void *mem, ofdn_t n);
extern void ofd_init(int (*write)(const char *, size_t len));

static inline int ofd_strstr(const char *s, int len, const char *str)
{
    int l = strlen(str);
    do {
        int n;

        if (len >= l && strstr(s, str))
            return 1;

        n = strnlen(s, len) + 1;
        len -= strnlen(s, len) + 1;
        s += n;
    } while (len > 0);
    return 0;
}

#endif /* _OF_DEVTREE_H */
