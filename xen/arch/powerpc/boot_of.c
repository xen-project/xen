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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/multiboot.h>
#include <xen/version.h>
#include <xen/spinlock.h>
#include <xen/serial.h>
#include <xen/time.h>
#include <asm/page.h>
#include <asm/io.h>
#include "exceptions.h"
#include "of-devtree.h"

static ulong of_vec;
static ulong of_msr;
static int of_out;
static ofdn_t boot_cpu;
static char bootargs[256];

#define COMMAND_LINE_SIZE 512
static char builtin_cmdline[COMMAND_LINE_SIZE]
    __attribute__((section("__builtin_cmdline"))) = CMDLINE;

extern struct ns16550_defaults ns16550;

#undef OF_DEBUG

#ifdef OF_DEBUG
#define DBG(args...) of_printf(args)
#else
#define DBG(args...)
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
extern s32 prom_call(void *arg, ulong rtas_base, ulong func, ulong msr);

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
    DBG("finddevice %s -> %d\n",devspec, rets[0]);
    return rets[0];
}

static int __init of_getprop(int ph, const char *name, void *buf, u32 buflen)
{
    int rets[1] = { OF_FAILURE };

    of_call("getprop", 4, 1, rets, ph, name, buf, buflen);

    if (rets[0] == OF_FAILURE) {
        DBG("getprop 0x%x %s -> FAILURE\n", ph, name);
        return OF_FAILURE;
    }

    DBG("getprop 0x%x %s -> 0x%x (%s)\n", ph, name, rets[0], (char *)buf);
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

    DBG("setprop 0x%x %s -> %s\n", ph, name, (char *)buf);
    return rets[0];
}

/*
 * returns 0 if there are no children (of spec)
 */
static int __init of_getchild(int ph)
{
    int rets[1] = { OF_FAILURE };

    of_call("child", 1, 1, rets, ph);
    DBG("getchild 0x%x -> 0x%x\n", ph, rets[0]);

    return rets[0];
}

/*
 * returns 0 is there are no peers
 */
static int __init of_getpeer(int ph)
{
    int rets[1] = { OF_FAILURE };

    of_call("peer", 1, 1, rets, ph);
    DBG("getpeer 0x%x -> 0x%x\n", ph, rets[0]);

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
    DBG("getproplen 0x%x %s -> 0x%x\n", ph, name, rets[0]);
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
    DBG("%s 0x%x %s -> 0x%x\n", __func__, ph, buffer, rets[0]);
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

    DBG("nextprop 0x%x %s -> %s\n", ph, name, (char *)buf);
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
    int rets[1] = { OF_FAILURE };

    if ( of_call("start-cpu", 3, 0, rets, cpu, pc, reg) == OF_FAILURE )
        return OF_FAILURE;

    return rets[0];
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

static int __init of_claim(void * virt, u32 size)
{
    int rets[1] = { OF_FAILURE };
    
    of_call("claim", 3, 1, rets, virt, size, 0/*align*/);
    if (rets[0] == OF_FAILURE) {
        DBG("%s 0x%p 0x%08x -> FAIL\n", __func__, virt, size);
        return OF_FAILURE;
    }

    DBG("%s 0x%p 0x%08x -> 0x%x\n", __func__, virt, size, rets[0]);
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

    DBG("getparent 0x%x -> 0x%x\n", ph, rets[0]);
    return rets[0];
}

static void boot_of_probemem(multiboot_info_t *mbi)
{
    int root;
    int p;
    u32 addr_cells = 1;
    u32 size_cells = 1;
    int rc;
    int mcount = 0;
    static memory_map_t mmap[16];

    root = of_finddevice("/");
    p = of_getchild(root);

    /* code is writen to assume sizes of 1 */
    of_getprop(root, "#address-cells", &addr_cells, sizeof (addr_cells));
    of_getprop(root, "#size-cells", &size_cells, sizeof (size_cells));
    DBG("%s: address_cells=%d  size_cells=%d\n",
                    __func__, addr_cells, size_cells);
    
    do {
        const char memory[] = "memory";
        char type[32];

        type[0] = '\0';

        of_getprop(p, "device_type", type, sizeof (type));
        if (strncmp(type, memory, sizeof (memory)) == 0) {
            u32 reg[48];  
            u32 al, ah, ll, lh;
            int r;

            rc = of_getprop(p, "reg", reg, sizeof (reg));
            if (rc == OF_FAILURE) {
                of_panic("no reg property for memory node: 0x%x.\n", p);
            }
            int l = rc/sizeof(u32); /* number reg element */
            DBG("%s: number of bytes in property 'reg' %d\n",
                            __func__, rc);
            
            r = 0;
            while (r < l) {
                al = ah = ll = lh = 0;
                if (addr_cells == 2) {
                    ah = reg[r++];
                    if (r >= l)
                        break;  /* partial line.  Skip  */
                    al = reg[r++];
                    if (r >= l)
                        break;  /* partial line.  Skip */
                } else {
                    al = reg[r++];
                    if (r >= l)
                        break;  /* partial line.  Skip */
                }
                if (size_cells == 2) {
                    lh = reg[r++];
                    if (r >= l)
                        break;  /* partial line.  Skip */
                    ll = reg[r++];
                } else {
                    ll = reg[r++];
                }

                if ((ll != 0) || (lh != 0)) {
                    mmap[mcount].size = 20; /* - size field */
                    mmap[mcount].type = 1; /* Regular ram */
                    mmap[mcount].length_high = lh;
                    mmap[mcount].length_low = ll;
                    mmap[mcount].base_addr_high = ah;
                    mmap[mcount].base_addr_low = al;
                    of_printf("%s: memory 0x%016lx[0x%08lx]\n",
                      __func__,
                      (u64)(((u64)mmap[mcount].base_addr_high << 32)
                            | mmap[mcount].base_addr_low),
                      (u64)(((u64)mmap[mcount].length_high << 32)
                            | mmap[mcount].length_low));
                    ++mcount;
                }
            }
        }
        p = of_getpeer(p);
    } while (p != OF_FAILURE && p != 0);

    if (mcount > 0) {
        mbi->flags |= MBI_MEMMAP;
        mbi->mmap_length = sizeof (mmap[0]) * mcount;
        mbi->mmap_addr = (ulong)mmap;
    }
}

static void boot_of_bootargs(multiboot_info_t *mbi)
{
    int rc;

    rc = of_getprop(bof_chosen, "bootargs", &bootargs, sizeof (bootargs));
    if (rc == OF_FAILURE || bootargs[0] == '\0') {
        strlcpy(bootargs, builtin_cmdline, sizeof(bootargs));
    }

    mbi->flags |= MBI_CMDLINE;
    mbi->cmdline = (u32)bootargs;

    of_printf("bootargs = %s\n", bootargs);
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
                if (actual > sz) of_panic("obj too small");
            }

            if (strncmp(name, name_str, sizeof(name_str)) == 0) {
                found_name = 1;
            }

            if (strncmp(name, devtype_str, sizeof(devtype_str)) == 0) {
                found_device_type = 1;
            }

            pos = ofd_prop_add(m, n, name, obj, actual);
            if (pos == 0) of_panic("prop_create");
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
        if (sz == OF_FAILURE) of_panic("bad path\n");

        nnext = ofd_node_child_create(m, n, path, sz);
        if (nnext == 0) of_panic("out of mem\n");

        do_pkg(m, nnext, pnext, path, psz);
    }

    /* do peer */
    pnext = of_getpeer(p);

    if (pnext != 0) {
        sz = of_package_to_path(pnext, path, psz);

        nnext = ofd_node_peer_create(m, n, path, sz);
        if (nnext <= 0) of_panic("out of space in OFD tree.\n");

        n = nnext;
        p = pnext;
        goto retry;
    }
}

static int pkg_save(void *mem)
{
    int root;
    char path[256];
    int r;

    path[0]='/';
    path[1]='\0';

    /* get root */
    root = of_getpeer(0);
    if (root == OF_FAILURE) of_panic("no root package\n");

    do_pkg(mem, OFD_ROOT, root, path, sizeof(path));

    r = (((ofdn_t *)mem)[1] + 1) * sizeof (u64);

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
            if (path == NULL) of_panic("no path to found prop: %s\n", name);

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
            if (dp <= 0) of_panic("no ofd node for OF node[0x%x]: %s\n",
                                  ref, ofpath);

            ref = dp;

            upd = ofd_prop_add(mem, c, name, &ref, sizeof(ref));
            if (upd <= 0) of_panic("update failed: %s\n", name);

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
    if (ch == OF_FAILURE) of_panic("/chosen not found\n");

    rc = of_getprop(ch, "cpu", &val, sizeof (val));

    if (rc != OF_FAILURE) {
        rc = of_instance_to_path(val, ofpath, sizeof (ofpath));

        if (rc > 0) {
            dn = ofd_node_find(mem, ofpath);
            if (dn <= 0) of_panic("no node for: %s\n", ofpath);

            boot_cpu = dn;
            val = dn;

            dn = ofd_node_find(mem, "/chosen");
            if (dn <= 0) of_panic("no /chosen node\n");

            dc = ofd_prop_add(mem, dn, "cpu", &val, sizeof (val));
            if (dc <= 0) of_panic("could not fix /chosen/cpu\n");
            rc = 1;
        } else {
            of_printf("*** can't find path to booting cpu, "
                    "SMP is disabled\n");
            boot_cpu = -1;
        }
    }
    return rc;
}

static ulong space_base;
static ulong find_space(u32 size, ulong align, multiboot_info_t *mbi)
{
    memory_map_t *map = (memory_map_t *)((ulong)mbi->mmap_addr);
    ulong eomem = ((u64)map->length_high << 32) | (u64)map->length_low;
    ulong base;

    of_printf("%s base=0x%016lx  eomem=0x%016lx  size=0x%08x  align=0x%lx\n",
                    __func__, space_base, eomem, size, align);
    base = ALIGN_UP(space_base, PAGE_SIZE);
    if ((base + size) >= 0x4000000) return 0;
    if (base + size > eomem) of_panic("not enough RAM\n");

    if (size == 0) return base;
    if (of_claim((void*)base, size) != OF_FAILURE) {
        space_base = base + size;
        return base;
    } else {
        for(base += 0x100000; (base+size) < 0x4000000; base += 0x100000) {
            of_printf("Trying 0x%016lx\n", base);
            if (of_claim((void*)base, size) != OF_FAILURE) {
                space_base = base + size;
                return base;
            }
        }
        return 0;
    }
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
    
static int __init boot_of_serial(void *oftree)
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

    /* prune this from the oftree */
    rc = of_package_to_path(n, buf, sizeof(buf));
    if (rc == OF_FAILURE) {
        of_panic("package-to-path of /chosen/stdout: failed\n");
    }
    of_printf("Pruning from devtree: %s\n"
              "  since Xen will be using it for console\n", buf);
    rc = ofd_prune_path(oftree, buf);
    if (rc < 0) {
        of_panic("prune path \"%s\" failed\n", buf);
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
    ns16550.io_base = val[1];

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

static void boot_of_module(ulong r3, ulong r4, multiboot_info_t *mbi)
{
    static module_t mods[3];
    void *oftree;
    ulong oftree_sz = 48 * PAGE_SIZE;
    char *mod0_start;
    ulong mod0_size;
    ulong mod0;
    static const char sepr[] = " -- ";
    extern char dom0_start[] __attribute__ ((weak));
    extern char dom0_size[] __attribute__ ((weak));
    const char *p;

    if ((r3 > 0) && (r4 > 0)) {
        /* was it handed to us in registers ? */
        mod0_start = (void *)r3;
        mod0_size = r4;
    } else {
        /* see if it is in the boot params */
        p = strstr((char *)((ulong)mbi->cmdline), "dom0_start=");
        if ( p != NULL) {
            p += 11;
            mod0_start = (char *)simple_strtoul(p, NULL, 0);

            p = strstr((char *)((ulong)mbi->cmdline), "dom0_size=");
            p += 10;
            mod0_size = simple_strtoul(p, NULL, 0);

            of_printf("mod0: %o %c %c %c\n",
                      mod0_start[0],
                      mod0_start[1],
                      mod0_start[2],
                      mod0_start[3]);

        } else if ( ((ulong)dom0_start != 0) && ((ulong)dom0_size != 0) ) {
            /* was it linked in ? */
        
            mod0_start = dom0_start;
            mod0_size = (ulong)dom0_size;
            of_printf("%s: linked in module copied after _end "
                      "(start 0x%p size 0x%lx)\n",
                      __func__, mod0_start, mod0_size);
        } else {
            mod0_start = _end;
            mod0_size = 0;
        }
    }

    space_base = (ulong)_end;
    mod0 = find_space(mod0_size, PAGE_SIZE, mbi);

    /* three cases
     * 1) mod0_size is not 0 and the image can be copied
     * 2) mod0_size is not 0 and the image cannot be copied
     * 3) mod0_size is 0
     */
    if (mod0_size > 0) {
        if (mod0 != 0) {
            memcpy((void *)mod0, mod0_start, mod0_size);
            mods[0].mod_start = mod0;
            mods[0].mod_end = mod0 + mod0_size;
        } else {
            of_panic("No space to copy mod0\n");
        }
    } else {
        mods[0].mod_start = mod0;
        mods[0].mod_end = mod0;
    }

    of_printf("%s: mod[0] @ 0x%016x[0x%x]\n", __func__,
              mods[0].mod_start, mods[0].mod_end);
    p = strstr((char *)(ulong)mbi->cmdline, sepr);
    if (p != NULL) {
        p += sizeof (sepr) - 1;
        mods[0].string = (u32)(ulong)p;
        of_printf("%s: mod[0].string: %s\n", __func__, p);
    }

    /* snapshot the tree */
    oftree = (void*)find_space(oftree_sz, PAGE_SIZE, mbi);
    if (oftree == 0) of_panic("Could not allocate OFD tree\n");

    of_printf("creating oftree\n");
    of_test("package-to-path");
    ofd_create(oftree, oftree_sz);
    pkg_save(oftree);

    boot_of_fixup_refs(oftree);
    boot_of_fixup_chosen(oftree);

    ofd_walk(oftree, OFD_ROOT, /* add_hype_props */ NULL, 2);

    mods[1].mod_start = (ulong)oftree;
    mods[1].mod_end = mods[1].mod_start + oftree_sz;
    of_printf("%s: mod[1] @ 0x%016x[0x%x]\n", __func__,
              mods[1].mod_start, mods[1].mod_end);


    mbi->flags |= MBI_MODULES;
    mbi->mods_count = 2;
    mbi->mods_addr = (u32)mods;

    boot_of_serial(oftree);
}

static int __init boot_of_cpus(void)
{
    int cpus;
    int cpu;
    int result;
    u32 cpu_clock[2];

    cpus = of_finddevice("/cpus");
    cpu = of_getchild(cpus);
    result = of_getprop(cpu, "timebase-frequency", &timebase_freq,
            sizeof(timebase_freq));
    if (result == OF_FAILURE) {
        of_panic("Couldn't get timebase frequency!\n");
    }
    of_printf("OF: timebase-frequency = %d Hz\n", timebase_freq);

    result = of_getprop(cpu, "clock-frequency", &cpu_clock, sizeof(cpu_clock));
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

    /* FIXME: should not depend on the boot CPU bring the first child */
    cpu = of_getpeer(cpu);
    while (cpu > 0) {
        of_start_cpu(cpu, (ulong)spin_start, 0);
        cpu = of_getpeer(cpu);
    }
    return 1;
}

static int __init boot_of_rtas(void)
{
    return 1;
}

multiboot_info_t __init *boot_of_init(
        ulong r3, ulong r4, ulong vec, ulong r6, ulong r7, ulong orig_msr)
{
    static multiboot_info_t mbi;

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
        of_printf("Hmm.. OF[0x%lx] seems to have stepped on our image "
                "that ranges: %p .. %p.\n HANG!\n",
                vec, _start, _end);
    }
    of_printf("%s: _start %p _end %p 0x%lx\n", __func__, _start, _end, r6);

    boot_of_fix_maple();
    boot_of_probemem(&mbi);
    boot_of_bootargs(&mbi);
    boot_of_module(r3, r4, &mbi);
    boot_of_cpus();
    boot_of_rtas();

    /* end of OF */
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
