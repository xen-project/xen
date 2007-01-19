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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/multiboot.h>
#include <xen/version.h>
#include <xen/spinlock.h>
#include <xen/serial.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <asm/page.h>
#include <asm/io.h>
#include "exceptions.h"
#include "of-devtree.h"
#include "oftree.h"
#include "rtas.h"

/* Secondary processors use this for handshaking with main processor.  */
volatile unsigned int __spin_ack;

static ulong of_vec;
static ulong of_msr;
static int of_out;
static ulong eomem;

/* Track memory during early boot with a limited per-page bitmap. We need an
 * allocator to tell us where we can place RTAS, our copy of the device tree.
 * We could examine the "available" properties in memory nodes, but we
 * apparently can't depend on firmware to update those when we call "claim". So
 * we need to track it ourselves.
 * We can't dynamically allocate the bitmap, because we would need something
 * to tell us where it's safe to allocate...
 */
#define MEM_AVAILABLE_PAGES ((32 << 20) >> PAGE_SHIFT)
static DECLARE_BITMAP(mem_available_pages, MEM_AVAILABLE_PAGES);

extern char builtin_cmdline[];
extern struct ns16550_defaults ns16550;

#undef OF_DEBUG
#undef OF_DEBUG_LOW

#ifdef OF_DEBUG
#define DBG(args...) of_printf(args)
#else
#define DBG(args...)
#endif

#ifdef OF_DEBUG_LOW
#define DBG_LOW(args...) of_printf(args)
#else
#define DBG_LOW(args...)
#endif

#define of_panic(MSG...) \
    do { of_printf(MSG); of_printf("\nHANG\n"); for (;;); } while (0)

struct of_service {
    u32 ofs_service;
    u32 ofs_nargs;
    u32 ofs_nrets;
    u32 ofs_args[10];
};

static int bof_chosen;

static struct of_service s;

static int __init of_call(
    const char *service, u32 nargs, u32 nrets, s32 rets[], ...)
{
    int rc;

    if (of_vec != 0) {
        va_list args;
        int i;
        memset(&s, 0, sizeof (s));
        s.ofs_service = (ulong)service;
        s.ofs_nargs = nargs;
        s.ofs_nrets = nrets;
        s.ofs_nargs = nargs;

        /* copy all the params into the args array */
        va_start(args, rets);

        for (i = 0; i < nargs; i++) {
            s.ofs_args[i] = va_arg(args, u32);
        }

        va_end(args);

        rc = prom_call(&s, 0, of_vec, of_msr);

        /* yes always to the copy, just in case */
        for (i = 0; i < nrets; i++) {
            rets[i] = s.ofs_args[i + nargs];
        }
    } else {
        rc = OF_FAILURE;
    }
    return rc;
}

/* popular OF methods */
static int __init _of_write(int ih, const char *addr, u32 len)
{
    int rets[1] = { OF_FAILURE };
    if (of_call("write", 3, 1, rets, ih, addr, len) == OF_FAILURE) {
        return OF_FAILURE;
    }
    return rets[0];
}

/* popular OF methods */
static int __init of_write(int ih, const char *addr, u32 len)
{
    int rc;
    int i = 0;
    int sum = 0;

    while (i < len) {
        if (addr[i] == '\n') {
            if (i > 0) {
                rc = _of_write(ih, addr, i);
                if (rc == OF_FAILURE)
                    return rc;
                sum += rc;
            }
            rc = _of_write(ih, "\r\n", 2);
            if (rc == OF_FAILURE)
                return rc;
            sum += rc;
            i++;
            addr += i;
            len -= i;
            i = 0;
            continue;
        }
        i++;
    }
    if (len > 0) {
        rc = _of_write(ih, addr, len);
        if (rc == OF_FAILURE)
            return rc;
        sum += rc;
    }
            
    return sum;
}

static int of_printf(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
static int __init of_printf(const char *fmt, ...)
{
    static char buf[1024];
    va_list args;
    int sz;

    if (of_out == 0) {
        return OF_FAILURE;
    }

    va_start(args, fmt);

    sz = vsnprintf(buf, sizeof (buf), fmt, args);
    if (sz <= sizeof (buf)) {
        of_write(of_out, buf, sz);
    } else {
        static const char trunc[] = "\n(TRUNCATED)\n";

        sz = sizeof (buf);
        of_write(of_out, buf, sz);
        of_write(of_out, trunc, sizeof (trunc));
    }
    return sz;
}

static int __init of_finddevice(const char *devspec)
{
    int rets[1] = { OF_FAILURE };

    of_call("finddevice", 1, 1, rets, devspec);
    if (rets[0] == OF_FAILURE) {
        DBG("finddevice %s -> FAILURE %d\n",devspec,rets[0]);
        return OF_FAILURE;
    }
    DBG_LOW("finddevice %s -> %d\n",devspec, rets[0]);
    return rets[0];
}

static int __init of_getprop(int ph, const char *name, void *buf, u32 buflen)
{
    int rets[1] = { OF_FAILURE };

    of_call("getprop", 4, 1, rets, ph, name, buf, buflen);

    if (rets[0] == OF_FAILURE) {
        DBG_LOW("getprop 0x%x %s -> FAILURE\n", ph, name);
        return OF_FAILURE;
    }

    DBG_LOW("getprop 0x%x %s -> 0x%x (%s)\n", ph, name, rets[0], (char *)buf);
    return rets[0];
}

static int __init of_setprop(
    int ph, const char *name, const void *buf, u32 buflen)
{
    int rets[1] = { OF_FAILURE };

    of_call("setprop", 4, 1, rets, ph, name, buf, buflen);

    if (rets[0] == OF_FAILURE) {
        DBG("setprop 0x%x %s -> FAILURE\n", ph, name);
        return OF_FAILURE;
    }

    DBG_LOW("setprop 0x%x %s -> %s\n", ph, name, (char *)buf);
    return rets[0];
}

/*
 * returns 0 if there are no children (of spec)
 */
static int __init of_getchild(int ph)
{
    int rets[1] = { OF_FAILURE };

    of_call("child", 1, 1, rets, ph);
    DBG_LOW("getchild 0x%x -> 0x%x\n", ph, rets[0]);

    return rets[0];
}

/*
 * returns 0 is there are no peers
 */
static int __init of_getpeer(int ph)
{
    int rets[1] = { OF_FAILURE };

    of_call("peer", 1, 1, rets, ph);
    DBG_LOW("getpeer 0x%x -> 0x%x\n", ph, rets[0]);

    return rets[0];
}

static int __init of_getproplen(int ph, const char *name)
{
    int rets[1] = { OF_FAILURE };

    of_call("getproplen", 2, 1, rets, ph, name);
    if (rets[0] == OF_FAILURE) {
        DBG("getproplen 0x%x %s -> FAILURE\n", ph, name);
        return OF_FAILURE;
    }
    DBG_LOW("getproplen 0x%x %s -> 0x%x\n", ph, name, rets[0]);
    return rets[0];
}

static int __init of_package_to_path(int ph, char *buffer, u32 buflen)
{
    int rets[1] = { OF_FAILURE };

    of_call("package-to-path", 3, 1, rets, ph, buffer, buflen);
    if (rets[0] == OF_FAILURE) {
        DBG("%s 0x%x -> FAILURE\n", __func__, ph);
        return OF_FAILURE;
    }
    DBG_LOW("%s 0x%x %s -> 0x%x\n", __func__, ph, buffer, rets[0]);
    if (rets[0] <= buflen)
        buffer[rets[0]] = '\0';
    return rets[0];
}

static int __init of_nextprop(int ph, const char *name, void *buf)
{
    int rets[1] = { OF_FAILURE };

    of_call("nextprop", 3, 1, rets, ph, name, buf);

    if (rets[0] == OF_FAILURE) {
        DBG("nextprop 0x%x %s -> FAILURE\n", ph, name);
        return OF_FAILURE;
    }

    DBG_LOW("nextprop 0x%x %s -> %s\n", ph, name, (char *)buf);
    return rets[0];
}

static int __init of_instance_to_path(int ih, char *buffer, u32 buflen)
{
    int rets[1] = { OF_FAILURE };

    if (of_call("instance-to-path", 3, 1, rets, ih, buffer, buflen)
         == OF_FAILURE)
        return OF_FAILURE;

    if (rets[0] <= buflen)
        buffer[rets[0]] = '\0';
    return rets[0];
}

static int __init of_start_cpu(int cpu, u32 pc, u32 reg)
{
    int ret;

    ret = of_call("start-cpu", 3, 0, NULL, cpu, pc, reg);

    return ret;
}

static void __init of_test(const char *of_method_name)
{
    int rets[1] = { OF_FAILURE };
    
    of_call("test", 1, 1, rets, of_method_name);
    if (rets[0] == OF_FAILURE ) {
        of_printf("Warning: possibly no OF method %s.\n"
                  "(Ignore this warning on PIBS.)\n", of_method_name);
    }
}

static int __init of_claim(u32 virt, u32 size, u32 align)
{
    int rets[1] = { OF_FAILURE };
    
    of_call("claim", 3, 1, rets, virt, size, align);
    if (rets[0] == OF_FAILURE) {
        DBG("%s 0x%08x 0x%08x  0x%08x -> FAIL\n", __func__, virt, size, align);
        return OF_FAILURE;
    }

    DBG_LOW("%s 0x%08x 0x%08x  0x%08x -> 0x%08x\n", __func__, virt, size, align,
        rets[0]);
    return rets[0];
}

static int __init of_instance_to_package(int ih)
{
    int rets[1] = { OF_FAILURE };

    of_call("instance-to-package", 1, 1, rets, ih);
    if (rets[0] == OF_FAILURE)
        return OF_FAILURE;

    return rets[0];
}

static int __init of_getparent(int ph)
{
    int rets[1] = { OF_FAILURE };

    of_call("parent", 1, 1, rets, ph);

    DBG_LOW("getparent 0x%x -> 0x%x\n", ph, rets[0]);
    return rets[0];
}

static int __init of_open(const char *devspec)
{
    int rets[1] = { OF_FAILURE };

    of_call("open", 1, 1, rets, devspec);
    return rets[0];
}

static void boot_of_alloc_init(int m, uint addr_cells, uint size_cells)
{
    int rc;
    uint pg;
    uint a[64];
    int tst;
    u64 start;
    u64 size;

    rc = of_getprop(m, "available", a, sizeof (a));
    if (rc > 0) {
        int l =  rc / sizeof(a[0]);
        int r = 0;

#ifdef OF_DEBUG
        { 
            int i;
            of_printf("avail:\n");
            for (i = 0; i < l; i += 4)
                of_printf("  0x%x%x, 0x%x%x\n",
                          a[i], a[i + 1],
                          a[i + 2] ,a[i + 3]);
        }
#endif
            
        pg = 0;
        while (pg < MEM_AVAILABLE_PAGES && r < l) {
            ulong end;

            start = a[r++];
            if (addr_cells == 2 && (r < l) )
                start = (start << 32) | a[r++];
            
            size = a[r++];
            if (size_cells == 2 && (r < l) )
                size = (size << 32) | a[r++];
                
            end = ALIGN_DOWN(start + size, PAGE_SIZE);

            start = ALIGN_UP(start, PAGE_SIZE);

            DBG("%s: marking 0x%x - 0x%lx\n", __func__,
                pg << PAGE_SHIFT, start);

            start >>= PAGE_SHIFT;
            while (pg < MEM_AVAILABLE_PAGES && pg < start) {
                set_bit(pg, mem_available_pages);
                pg++;
            }

            pg = end  >> PAGE_SHIFT;
        }
    }

    /* Now make sure we mark our own memory */
    pg =  (ulong)_start >> PAGE_SHIFT;
    start = (ulong)_end >> PAGE_SHIFT;

    DBG("%s: marking 0x%x - 0x%lx\n", __func__,
        pg << PAGE_SHIFT, start << PAGE_SHIFT);

    /* Lets try and detect if our image has stepped on something. It
     * is possible that FW has already subtracted our image from
     * available memory so we must make sure that the previous bits
     * are the same for the whole image */
    tst = test_and_set_bit(pg, mem_available_pages);
    ++pg;
    while (pg <= start) {
        if (test_and_set_bit(pg, mem_available_pages) != tst)
            of_panic("%s: pg :0x%x of our image is different\n",
                     __func__, pg);
        ++pg;
    }

    DBG("%s: marking 0x%x - 0x%x\n", __func__,
        0 << PAGE_SHIFT, 3 << PAGE_SHIFT);
    /* First for pages (where the vectors are) should be left alone as well */
    set_bit(0, mem_available_pages);
    set_bit(1, mem_available_pages);
    set_bit(2, mem_available_pages);
    set_bit(3, mem_available_pages);
}

#ifdef BOOT_OF_FREE
/* this is here in case we ever need a free call at a later date */
static void boot_of_free(ulong addr, ulong size)
{
    ulong bits;
    ulong pos;
    ulong i;

    size = ALIGN_UP(size, PAGE_SIZE);
    bits = size >> PAGE_SHIFT;
    pos = addr >> PAGE_SHIFT;

    for (i = 0; i < bits; i++) {
        if (!test_and_clear_bit(pos + i, mem_available_pages))
            of_panic("%s: pg :0x%lx was never allocated\n",
                     __func__, pos + i);
    }
}
#endif

static ulong boot_of_alloc(ulong size)
{
    ulong bits;
    ulong pos;

    if (size == 0)
        return 0;

    DBG("%s(0x%lx)\n", __func__, size);

    size = ALIGN_UP(size, PAGE_SIZE);
    bits = size >> PAGE_SHIFT;
    pos = 0;
    for (;;) {
        ulong i;

        pos = find_next_zero_bit(mem_available_pages,
                                 MEM_AVAILABLE_PAGES, pos);
        DBG("%s: found start bit at: 0x%lx\n", __func__, pos);

        /* found nothing */
        if ((pos + bits) > MEM_AVAILABLE_PAGES) {
            of_printf("%s: allocation of size: 0x%lx failed\n",
                     __func__, size);
            return 0;
        }

        /* find a set that fits */
        DBG("%s: checking for 0x%lx bits: 0x%lx\n", __func__, bits, pos);

        i = find_next_bit(mem_available_pages, MEM_AVAILABLE_PAGES, pos);  
        if (i - pos >= bits) {
            uint addr = pos << PAGE_SHIFT;

            /* make sure OF is happy with our choice */
            if (of_claim(addr, size, 0) != OF_FAILURE) {
                for (i = 0; i < bits; i++)
                    set_bit(pos + i, mem_available_pages);

                DBG("%s: 0x%lx is good returning 0x%x\n",
                    __func__, pos, addr);
                return addr;
            }
            /* if OF did not like the address then simply start from
             * the next bit */
            i = 1;
        }

        pos = pos + i;
    }
}

int boot_of_mem_avail(int pos, ulong *startpage, ulong *endpage)
{
    ulong freebit;
    ulong usedbit;

    if (pos >= MEM_AVAILABLE_PAGES)
        /* Stop iterating. */
        return -1;

    /* Find first free page. */
    freebit = find_next_zero_bit(mem_available_pages, MEM_AVAILABLE_PAGES, pos);
    if (freebit >= MEM_AVAILABLE_PAGES) {
        /* We know everything after MEM_AVAILABLE_PAGES is still free. */
        *startpage = MEM_AVAILABLE_PAGES << PAGE_SHIFT;
        *endpage = ~0UL;
        return freebit;
    }
    *startpage = freebit << PAGE_SHIFT;

    /* Now find first used page after that. */
    usedbit = find_next_bit(mem_available_pages, MEM_AVAILABLE_PAGES, freebit);
    if (usedbit >= MEM_AVAILABLE_PAGES) {
        /* We know everything after MEM_AVAILABLE_PAGES is still free. */
        *endpage = ~0UL;
        return usedbit;
    }

    *endpage = usedbit << PAGE_SHIFT;
    return usedbit;
}

static ulong boot_of_mem_init(void)
{
    int root;
    int p;
    int rc;
    uint addr_cells;
    uint size_cells;

    root = of_finddevice("/");
    p = of_getchild(root);

    /* code is writen to assume sizes of 1 */
    of_getprop(root, "#address-cells", &addr_cells,
               sizeof (addr_cells));
    of_getprop(root, "#size-cells", &size_cells,
               sizeof (size_cells));
    DBG("%s: address_cells=%d  size_cells=%d\n",
                    __func__, addr_cells, size_cells);

    /* We do ream memory discovery later, for now we only want to find
     * the first LMB */
    do {
        const char memory[] = "memory";
        char type[32];

        type[0] = '\0';

        of_getprop(p, "device_type", type, sizeof (type));
        if (strncmp(type, memory, sizeof (memory)) == 0) {
            uint reg[48];  
            u64 start;
            u64 size;
            int r;
            int l;

            rc = of_getprop(p, "reg", reg, sizeof (reg));
            if (rc == OF_FAILURE) {
                of_panic("no reg property for memory node: 0x%x.\n", p);
            }

            l = rc / sizeof(reg[0]); /* number reg element */
            DBG("%s: number of bytes in property 'reg' %d\n",
                            __func__, rc);
            
            r = 0;
            while (r < l) {
                start = reg[r++];
                if (addr_cells == 2 && (r < l) )
                    start = (start << 32) | reg[r++];

                if (r >= l)
                    break;  /* partial line.  Skip */

                if (start > 0) {
                    /* this is not the first LMB so we skip it */
                    break;
                }

                size = reg[r++];
                if (size_cells == 2 && (r < l) )
                    size = (size << 32) | reg[r++];
                
                if (r > l)
                    break;  /* partial line.  Skip */

                boot_of_alloc_init(p, addr_cells, size_cells);
                
                eomem = size;
                return size;
            }
        }
        p = of_getpeer(p);
    } while (p != OF_FAILURE && p != 0);

    return 0;
}

static void boot_of_bootargs(multiboot_info_t *mbi)
{
    int rc;

    if (builtin_cmdline[0] == '\0') {
        rc = of_getprop(bof_chosen, "bootargs", builtin_cmdline,
                CONFIG_CMDLINE_SIZE);
        if (rc > CONFIG_CMDLINE_SIZE)
            of_panic("bootargs[] not big enough for /chosen/bootargs\n");
    }

    mbi->flags |= MBI_CMDLINE;
    mbi->cmdline = (ulong)builtin_cmdline;

    of_printf("bootargs = %s\n", builtin_cmdline);
}

static int save_props(void *m, ofdn_t n, int pkg)
{
    int ret;
    char name[128];
    int result = 1;
    int found_name = 0;
    int found_device_type = 0;
    const char name_str[] = "name";
    const char devtype_str[] = "device_type";

    /* get first */
    result = of_nextprop(pkg, 0, name);

    while (result > 0) {
        int sz;
        u64 obj[1024];

        sz = of_getproplen(pkg, name);
        if (sz >= 0) {
            ret = OF_SUCCESS;
        } else {
            ret = OF_FAILURE;
        }

        if (ret == OF_SUCCESS) {
            int actual = 0;
            ofdn_t pos;

            if (sz > 0) {
                if (sz > sizeof (obj)) {
                    of_panic("obj array not big enough for 0x%x\n", sz);
                }
                actual = of_getprop(pkg, name, obj, sz);
                if (actual > sz)
                    of_panic("obj too small");
            }

            if (strncmp(name, name_str, sizeof(name_str)) == 0) {
                found_name = 1;
            }

            if (strncmp(name, devtype_str, sizeof(devtype_str)) == 0) {
                found_device_type = 1;
            }

            pos = ofd_prop_add(m, n, name, obj, actual);
            if (pos == 0)
                of_panic("prop_create");
        }

        result = of_nextprop(pkg, name, name);
    }

    return 1;
}


static void do_pkg(void *m, ofdn_t n, int p, char *path, size_t psz)
{
    int pnext;
    ofdn_t nnext;
    int sz;

retry:
    save_props(m, n, p);

    /* do children first */
    pnext = of_getchild(p);

    if (pnext != 0) {
        sz = of_package_to_path(pnext, path, psz);
        if (sz == OF_FAILURE)
            of_panic("bad path\n");

        nnext = ofd_node_child_create(m, n, path, sz);
        if (nnext == 0)
            of_panic("out of mem\n");

        do_pkg(m, nnext, pnext, path, psz);
    }

    /* do peer */
    pnext = of_getpeer(p);

    if (pnext != 0) {
        sz = of_package_to_path(pnext, path, psz);

        nnext = ofd_node_peer_create(m, n, path, sz);
        if (nnext <= 0)
            of_panic("out of space in OFD tree.\n");

        n = nnext;
        p = pnext;
        goto retry;
    }
}

static long pkg_save(void *mem)
{
    int root;
    char path[256];
    int r;

    path[0]='/';
    path[1]='\0';

    /* get root */
    root = of_getpeer(0);
    if (root == OF_FAILURE)
        of_panic("no root package\n");

    do_pkg(mem, OFD_ROOT, root, path, sizeof(path));

    r = ofd_size(mem);

    of_printf("%s: saved device tree in 0x%x bytes\n", __func__, r);

    return r;
}

static int boot_of_fixup_refs(void *mem)
{
    static const char *fixup_props[] = {
        "interrupt-parent",
    };
    int i;
    int count = 0;

    for (i = 0; i < ARRAY_SIZE(fixup_props); i++) {
        ofdn_t c;
        const char *name = fixup_props[i];

        c = ofd_node_find_by_prop(mem, OFD_ROOT, name, NULL, 0);
        while (c > 0) {
            const char *path;
            int rp;
            int ref;
            ofdn_t dp;
            int rc;
            ofdn_t upd;
            char ofpath[256];

            path = ofd_node_path(mem, c);
            if (path == NULL)
                of_panic("no path to found prop: %s\n", name);

            rp = of_finddevice(path);
            if (rp == OF_FAILURE)
                of_panic("no real device for: name %s, path %s\n",
                          name, path);
            /* Note: In theory 0 is a valid node handle but it is highly
             * unlikely.
             */
            if (rp == 0) {
                of_panic("%s: of_finddevice returns 0 for path %s\n",
                                    __func__, path);
            } 

            rc = of_getprop(rp, name, &ref, sizeof(ref));
            if ((rc == OF_FAILURE) || (rc == 0))
                of_panic("no prop: name %s, path %s, device 0x%x\n",
                         name, path, rp);

            rc = of_package_to_path(ref, ofpath, sizeof (ofpath));
            if (rc == OF_FAILURE)
                of_panic("no package: name %s, path %s, device 0x%x,\n"
                         "ref 0x%x\n", name, path, rp, ref);

            dp = ofd_node_find(mem, ofpath);
            if (dp <= 0)
                of_panic("no ofd node for OF node[0x%x]: %s\n",
                         ref, ofpath);

            ref = dp;

            upd = ofd_prop_add(mem, c, name, &ref, sizeof(ref));
            if (upd <= 0)
                of_panic("update failed: %s\n", name);

#ifdef DEBUG
            of_printf("%s: %s/%s -> %s\n", __func__,
                    path, name, ofpath);
#endif
            ++count;
            c = ofd_node_find_next(mem, c);
        }
    }
    return count;
}

static int boot_of_fixup_chosen(void *mem)
{
    int ch;
    ofdn_t dn;
    ofdn_t dc;
    int val;
    int rc;
    char ofpath[256];

    ch = of_finddevice("/chosen");
    if (ch == OF_FAILURE)
        of_panic("/chosen not found\n");

    rc = of_getprop(ch, "cpu", &val, sizeof (val));

    if (rc != OF_FAILURE) {
        rc = of_instance_to_path(val, ofpath, sizeof (ofpath));

        if (rc > 0) {
            dn = ofd_node_find(mem, ofpath);
            if (dn <= 0)
                of_panic("no node for: %s\n", ofpath);

            ofd_boot_cpu = dn;
            val = dn;

            dn = ofd_node_find(mem, "/chosen");
            if (dn <= 0)
                of_panic("no /chosen node\n");

            dc = ofd_prop_add(mem, dn, "cpu", &val, sizeof (val));
            if (dc <= 0)
                of_panic("could not fix /chosen/cpu\n");
            rc = 1;
        } else {
            of_printf("*** can't find path to booting cpu, "
                    "SMP is disabled\n");
            ofd_boot_cpu = -1;
        }
    }
    return rc;
}

/* PIBS Version 1.05.0000 04/26/2005 has an incorrect /ht/isa/ranges
 * property.  The values are bad, and it doesn't even have the
 * right number of cells. */

static void __init boot_of_fix_maple(void)
{
    int isa;
    const char *ranges = "ranges";
    u32 isa_ranges[3];
    const u32 isa_test[] = { 0x00000001, 0xf4000000, 0x00010000 };
    const u32 isa_fixed[] = {
        0x00000001,
        0x00000000,
        0x00000000, /* 0xf4000000, matt says this */
        0x00000000,
        0x00000000,
        0x00010000
    };

    isa = of_finddevice("/ht@0/isa@4");
    if (isa != OF_FAILURE) {
        if (of_getproplen(isa, ranges) == sizeof (isa_test)) {
            of_getprop(isa, ranges, isa_ranges, sizeof (isa_ranges));
            if (memcmp(isa_ranges, isa_test, sizeof (isa_test)) == 0) {
                int rc;

                of_printf("OF: fixing bogus ISA range on maple\n");
                rc = of_setprop(isa, ranges, isa_fixed, sizeof (isa_fixed));
                if (rc == OF_FAILURE) {
                    of_panic("of_setprop() failed\n");
                }
            }
        }
    }
}
    
static int __init boot_of_serial(void *oft)
{
    int n;
    int p;
    int rc;
    u32 val[3];
    char buf[128];

    n = of_instance_to_package(of_out);
    if (n == OF_FAILURE) {
        of_panic("instance-to-package of /chosen/stdout: failed\n");
    }
    
    /* Prune all serial devices from the device tree, including the
     * one pointed to by /chosen/stdout, because a guest domain can
     * initialize them and in so doing corrupt our console output.
     */
    for (p = n; p > 0; p = of_getpeer(p)) {
        char type[32];

        rc = of_package_to_path(p, buf, sizeof(buf));
        if (rc == OF_FAILURE)
            of_panic("package-to-path failed\n");

        rc = of_getprop(p, "device_type", type, sizeof (type));
        if (rc == OF_FAILURE) {
            of_printf("%s: fetching type of `%s' failed\n", __func__, buf);
            continue;
        }

        if (strcmp(type, "serial") != 0)
            continue;

        of_printf("pruning `%s' from devtree\n", buf);
        rc = ofd_prune_path(oft, buf);
        if (rc < 0)
            of_panic("prune of `%s' failed\n", buf);
    }

    p = of_getparent(n);
    if (p == OF_FAILURE) {
        of_panic("no parent for: 0x%x\n", n);
    }

    buf[0] = '\0';
    of_getprop(p, "device_type", buf, sizeof (buf));
    if (strstr(buf, "isa") == NULL) {
        of_panic("only ISA UARTS supported\n");
    }

    /* should get this from devtree */
    isa_io_base = 0xf4000000;
    of_printf("%s: ISA base: 0x%lx\n", __func__, isa_io_base);

    buf[0] = '\0';
    of_getprop(n, "device_type", buf, sizeof (buf));
    if (strstr(buf, "serial") == NULL) {
        of_panic("only UARTS supported\n");
    }

    rc = of_getprop(n, "reg", val, sizeof (val));
    if (rc == OF_FAILURE) {
        of_panic("%s: no location for serial port\n", __func__);
    }

    ns16550.baud = BAUD_AUTO;
    ns16550.data_bits = 8;
    ns16550.parity = 'n';
    ns16550.stop_bits = 1;

    rc = of_getprop(n, "interrupts", val, sizeof (val));
    if (rc == OF_FAILURE) {
        of_printf("%s: no ISRC, forcing poll mode\n", __func__);
        ns16550.irq = 0;
    } else {
        ns16550.irq = val[0];
        of_printf("%s: ISRC=0x%x, but forcing poll mode\n",
                  __func__, ns16550.irq);
        ns16550.irq = 0;
    }

    return 1;
}

static int __init boot_of_rtas(module_t *mod, multiboot_info_t *mbi)
{
    int rtas_node;
    int rtas_instance;
    uint size = 0;
    int res[2];
    int mem;
    int ret;

    rtas_node = of_finddevice("/rtas");

    if (rtas_node <= 0) {
        of_printf("No RTAS, Xen has no power control\n");
        return 0;
    }
    of_getprop(rtas_node, "rtas-size", &size, sizeof (size));
    if (size == 0) {
        of_printf("RTAS, has no size\n");
        return 0;
    }

    rtas_instance = of_open("/rtas");
    if (rtas_instance == OF_FAILURE) {
        of_printf("RTAS, could not open\n");
        return 0;
    }

    size = ALIGN_UP(size, PAGE_SIZE);
    
    mem = boot_of_alloc(size);
    if (mem == 0)
        of_panic("Could not allocate RTAS tree\n");

    of_printf("instantiating RTAS at: 0x%x\n", mem);

    ret = of_call("call-method", 3, 2, res,
                  "instantiate-rtas", rtas_instance, mem);
    if (ret == OF_FAILURE) {
        of_printf("RTAS, could not open\n");
        return 0;
    }
    
    rtas_entry = res[1];
    rtas_base = mem;
    rtas_end = mem + size;
    rtas_msr = of_msr;

    mod->mod_start = rtas_base;
    mod->mod_end = rtas_end;
    return 1;
}

static void * __init boot_of_devtree(module_t *mod, multiboot_info_t *mbi)
{
    void *oft;
    ulong oft_sz = 48 * PAGE_SIZE;

    /* snapshot the tree */
    oft = (void *)boot_of_alloc(oft_sz);
    if (oft == NULL)
        of_panic("Could not allocate OFD tree\n");

    of_printf("creating oftree at: 0x%p\n", oft);
    of_test("package-to-path");
    oft = ofd_create(oft, oft_sz);
    pkg_save(oft);

    if (ofd_size(oft) > oft_sz)
         of_panic("Could not fit all of native devtree\n");

    boot_of_fixup_refs(oft);
    boot_of_fixup_chosen(oft);

    if (ofd_size(oft) > oft_sz)
         of_panic("Could not fit all devtree fixups\n");

    ofd_walk(oft, __func__, OFD_ROOT, /* add_hype_props */ NULL, 2);

    mod->mod_start = (ulong)oft;
    mod->mod_end = mod->mod_start + oft_sz;
    of_printf("%s: devtree mod @ 0x%016x - 0x%016x\n", __func__,
              mod->mod_start, mod->mod_end);

    return oft;
}

static void * __init boot_of_module(ulong r3, ulong r4, multiboot_info_t *mbi)
{
    static module_t mods[4];
    ulong mod0_start;
    ulong mod0_size;
    static const char * sepr[] = {" -- ", " || "};
    int sepr_index;
    extern char dom0_start[] __attribute__ ((weak));
    extern char dom0_size[] __attribute__ ((weak));
    const char *p = NULL;
    int mod;
    void *oft;

    if ((r3 > 0) && (r4 > 0)) {
        /* was it handed to us in registers ? */
        mod0_start = r3;
        mod0_size = r4;
            of_printf("%s: Dom0 was loaded and found using r3/r4:"
                      "0x%lx[size 0x%lx]\n",
                      __func__, mod0_start, mod0_size);
    } else {
        /* see if it is in the boot params */
        p = strstr((char *)((ulong)mbi->cmdline), "dom0_start=");
        if ( p != NULL) {
            p += 11;
            mod0_start = simple_strtoul(p, NULL, 0);

            p = strstr((char *)((ulong)mbi->cmdline), "dom0_size=");
            p += 10;
            mod0_size = simple_strtoul(p, NULL, 0);
            of_printf("%s: Dom0 was loaded and found using cmdline:"
                      "0x%lx[size 0x%lx]\n",
                      __func__, mod0_start, mod0_size);
        } else if ( ((ulong)dom0_start != 0) && ((ulong)dom0_size != 0) ) {
            /* was it linked in ? */
        
            mod0_start = (ulong)dom0_start;
            mod0_size = (ulong)dom0_size;
            of_printf("%s: Dom0 is linked in: 0x%lx[size 0x%lx]\n",
                      __func__, mod0_start, mod0_size);
        } else {
            mod0_start = (ulong)_end;
            mod0_size = 0;
            of_printf("%s: FYI Dom0 is unknown, will be caught later\n",
                      __func__);
        }
    }

    if (mod0_size > 0) {
        const char *c = (const char *)mod0_start;

        of_printf("mod0: %o %c %c %c\n", c[0], c[1], c[2], c[3]);
    }

    mod = 0;
    mods[mod].mod_start = mod0_start;
    mods[mod].mod_end = mod0_start + mod0_size;

    of_printf("%s: dom0 mod @ 0x%016x[0x%x]\n", __func__,
              mods[mod].mod_start, mods[mod].mod_end);

    /* look for delimiter: "--" or "||" */
    for (sepr_index = 0; sepr_index < ARRAY_SIZE(sepr); sepr_index++){
        p = strstr((char *)(ulong)mbi->cmdline, sepr[sepr_index]);
        if (p != NULL)
            break;
    }

    if (p != NULL) {
        /* Xen proper should never know about the dom0 args.  */
        *(char *)p = '\0';
        p += strlen(sepr[sepr_index]);
        mods[mod].string = (u32)(ulong)p;
        of_printf("%s: dom0 mod string: %s\n", __func__, p);
    }

    ++mod;
    if (boot_of_rtas(&mods[mod], mbi))
        ++mod;

    oft = boot_of_devtree(&mods[mod], mbi);
    if (oft == NULL)
        of_panic("%s: boot_of_devtree failed\n", __func__);

    ++mod;

    mbi->flags |= MBI_MODULES;
    mbi->mods_count = mod;
    mbi->mods_addr = (u32)mods;

    return oft;
}

static int __init boot_of_cpus(void)
{
    int cpus_node, cpu_node;
    int bootcpu_instance, bootcpu_node;
    int logical;
    int result;
    s32 cpuid;
    u32 cpu_clock[2];
    extern uint cpu_hard_id[NR_CPUS];

    /* Look up which CPU we are running on right now and get all info
     * from there */
    result = of_getprop(bof_chosen, "cpu",
                        &bootcpu_instance, sizeof (bootcpu_instance));
    if (result == OF_FAILURE)
        of_panic("Failed to look up boot cpu instance\n");

    bootcpu_node = of_instance_to_package(bootcpu_instance);
    if (result == OF_FAILURE)
        of_panic("Failed to look up boot cpu package\n");

    cpu_node = bootcpu_node;

    result = of_getprop(cpu_node, "timebase-frequency", &timebase_freq,
            sizeof(timebase_freq));
    if (result == OF_FAILURE) {
        of_panic("Couldn't get timebase frequency!\n");
    }
    of_printf("OF: timebase-frequency = %d Hz\n", timebase_freq);

    result = of_getprop(cpu_node, "clock-frequency",
                        &cpu_clock, sizeof(cpu_clock));
    if (result == OF_FAILURE || (result !=4 && result != 8)) {
        of_panic("Couldn't get clock frequency!\n");
    }
    cpu_khz = cpu_clock[0];
    if (result == 8) {
        cpu_khz <<= 32;
        cpu_khz |= cpu_clock[1];
    }
    cpu_khz /= 1000;
    of_printf("OF: clock-frequency = %ld KHz\n", cpu_khz);

    /* We want a continuous logical cpu number space and we'll make
     * the booting CPU logical 0.  */
    cpu_set(0, cpu_present_map);
    cpu_set(0, cpu_online_map);
    cpu_set(0, cpu_possible_map);

    result = of_getprop(cpu_node, "reg", &cpuid, sizeof(cpuid));
    cpu_hard_id[0] = cpuid;

    /* Spin up all CPUS, even if there are more than NR_CPUS or we are
     * runnign nosmp, because Open Firmware has them spinning on cache
     * lines which will eventually be scrubbed, which could lead to
     * random CPU activation.
     */

    /* Find the base of the multi-CPU package node */
    cpus_node = of_finddevice("/cpus");
    if (cpus_node <= 0) {
        of_printf("Single Processor System\n");
        return 1;
    }
    /* Start with the first child */
    cpu_node = of_getchild(cpus_node);

    for (logical = 1; cpu_node > 0; logical++) {
        unsigned int ping, pong;
        unsigned long now, then, timeout;
        
        if (cpu_node == bootcpu_node) {
            /* same CPU as boot CPU shich we have already made 0 so
             * reduce the logical count */
            --logical;
        } else {
            result = of_getprop(cpu_node, "reg", &cpuid, sizeof(cpuid));
            if (result == OF_FAILURE)
                of_panic("cpuid lookup failed\n");

            cpu_hard_id[logical] = cpuid;

            of_printf("spinning up secondary processor #%d: ", logical);

            __spin_ack = ~0x0;
            ping = __spin_ack;
            pong = __spin_ack;
            of_printf("ping = 0x%x: ", ping);

            mb();
            result = of_start_cpu(cpu_node, (ulong)spin_start, logical);
            if (result == OF_FAILURE)
                of_panic("start cpu failed\n");

            /* We will give the secondary processor five seconds to reply.  */
            then = mftb();
            timeout = then + (5 * timebase_freq);

            do {
                now = mftb();
                if (now >= timeout) {
                    of_printf("BROKEN: ");
                    break;
                }

                mb();
                pong = __spin_ack;
            } while (pong == ping);
            of_printf("pong = 0x%x\n", pong);

            if (pong != ping) {
                cpu_set(logical, cpu_present_map);
                cpu_set(logical, cpu_possible_map);
            }
        }
        cpu_node = of_getpeer(cpu_node);
    }
    return 1;
}

multiboot_info_t __init *boot_of_init(
        ulong r3, ulong r4, ulong vec, ulong r6, ulong r7, ulong orig_msr)
{
    static multiboot_info_t mbi;
    void *oft;
    int r;

    of_vec = vec;
    of_msr = orig_msr;

    bof_chosen = of_finddevice("/chosen");
    of_getprop(bof_chosen, "stdout", &of_out, sizeof (of_out));

    of_printf("%s\n", "---------------------------------------------------");
    of_printf("OF: Xen/PPC version %d.%d%s (%s@%s) (%s) %s\n",
              xen_major_version(), xen_minor_version(), xen_extra_version(),
              xen_compile_by(), xen_compile_domain(),
              xen_compiler(), xen_compile_date());

    of_printf("%s args: 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n"
            "boot msr: 0x%lx\n",
            __func__,
            r3, r4, vec, r6, r7, orig_msr);

    if ((vec >= (ulong)_start) && (vec <= (ulong)_end)) {
        of_panic("Hmm.. OF[0x%lx] seems to have stepped on our image "
                "that ranges: %p .. %p.\n",
                vec, _start, _end);
    }
    of_printf("%s: _start %p _end %p 0x%lx\n", __func__, _start, _end, r6);

    boot_of_fix_maple();
    r = boot_of_mem_init();
    if (r == 0)
        of_panic("failure to initialize memory allocator");
    boot_of_bootargs(&mbi);
    oft = boot_of_module(r3, r4, &mbi);
    boot_of_cpus();
    boot_of_serial(oft);

    /* end of OF */
    of_printf("Quiescing Open Firmware ...\n");
    of_call("quiesce", 0, 0, NULL);

    return &mbi;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
