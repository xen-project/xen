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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _PFW_H
#define _PFW_H

#include <xen/types.h>
#include <public/xencomm.h>
#include <public/io/console.h>
#include <of-devtree.h>

#define MIN(x,y) (((x)<(y))?(x):(y))

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL<<PAGE_SHIFT)

struct ofh_args {
    u32 ofa_service;
    u32 ofa_nargs;
    u32 ofa_nreturns;
    s32 ofa_args[0];
};

typedef s32 (ofh_func_t)(u32, u32, s32 [], s32 [], ulong b);

struct ofh_srvc {
    const char *ofs_name;
    ofh_func_t *ofs_func;
    u32 ofs_hash;
};

extern ofh_func_t ofh_test_method;
extern ofh_func_t ofh_nosup;

/* device tree */
extern ofh_func_t ofh_peer;
extern ofh_func_t ofh_child;
extern ofh_func_t ofh_parent;
extern ofh_func_t ofh_instance_to_package;
extern ofh_func_t ofh_getproplen;
extern ofh_func_t ofh_getprop;
extern ofh_func_t ofh_nextprop;
extern ofh_func_t ofh_setprop;
extern ofh_func_t ofh_canon;
extern ofh_func_t ofh_finddevice;
extern ofh_func_t ofh_instance_to_path;
extern ofh_func_t ofh_package_to_path;
extern ofh_func_t ofh_call_method;

/* IO */
extern ofh_func_t ofh_open;
extern ofh_func_t ofh_close;
extern ofh_func_t ofh_read;
extern ofh_func_t ofh_write;
extern ofh_func_t ofh_seek;

/* memory */
extern ofh_func_t ofh_claim;
extern ofh_func_t ofh_release;

/* control */
extern ofh_func_t ofh_boot;
extern ofh_func_t ofh_enter;
extern ofh_func_t ofh_exit; /* __attribute__ ((noreturn)); */
extern ofh_func_t ofh_chain;
extern ofh_func_t ofh_quiesce;

extern struct ofh_srvc ofh_srvc[];
extern struct ofh_srvc ofh_isa_srvc[];
extern s32 ofh_active_package;

struct ofh_methods {
    const char *ofm_name;
    ofh_func_t *ofm_method;
};

struct ofh_ihandle {
    s32 (*ofi_close)(void);
    s32 (*ofi_read)(s32 chan, void *buf, u32 count, s32 *actual, ulong b);
    s32 (*ofi_write)(s32 chan, const void *buf, u32 count, s32 *actual,
                     ulong b);
    s32 (*ofi_seek)(u32 pos_hi, u32 pos_lo, u32 *status);
    struct ofh_methods *ofi_methods;
    struct xencons_interface *ofi_intf;
    s32 ofi_node;
    s32 ofi_chan;
};

struct ofh_imem {
    s32 (*ofi_xlate)(void *addr, u32 ret[4]);
};


enum prop_type {
    pt_byte_array,
    pt_value,
    pt_string,
    pt_composite,
    /* these are for our own use */
    pt_func,
};

extern s32 ofh_start(struct ofh_args *);

#define OFH_CONS_XEN -1
extern void ofh_cons_init(struct ofh_ihandle *ihp, ulong b);
extern s32 ofh_cons_read(s32 chan, void *buf, u32 count, s32 *actual);
extern s32 ofh_cons_write(const void *buf, u32 count, s32 *actual);
extern s32 ofh_cons_close(void);
extern s32 ofh_handler(struct ofh_args *args, ulong ifh_base);
extern s32 leap(u32 nargs, u32 nrets, s32 args[], s32 rets[],
                ulong ba, void *f);

extern s32 io_leap(s32 chan, void *buf, u32 sz, s32 *actual,
                ulong ba, void *f);

extern void ofh_vty_init(ofdn_t chosen, ulong b);
extern void ofh_rtas_init(ulong b);

extern void *_ofh_tree;

#if 1
#define DRELA(p,b) ((__typeof__ (p))((((ulong)(p)) + (b))))
#else
#define DRELA(p,b) (b == b ? p : 0)
#endif
extern ulong get_base(void);

static inline void *ofd_mem(ulong base) { return *DRELA(&_ofh_tree, base); }

extern ofh_func_t ofh_start_cpu;
extern ofh_func_t ofh_stop_self;
extern ofh_func_t ofh_idle_self;
extern ofh_func_t ofh_resume_cpu;

/* In Open Firmware, we only use xencomm for reading/writing console data.
 * Since that's always small, we can use this fixed-size structure. */
#define XENCOMM_MINI_ADDRS 3
struct xencomm_mini {
    struct xencomm_desc _desc;
    u64 address[XENCOMM_MINI_ADDRS];
};

extern int xencomm_create_mini(void *area, int arealen, void *buffer,
            unsigned long bytes, struct xencomm_desc **ret);

#endif
