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
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/version.h>
#include <public/xen.h>
#include "of-devtree.h"
#include "oftree.h"
#include "rtas.h"

#undef RTAS

ofdn_t ofd_boot_cpu;

#ifdef PAPR_VTERM
static ofdn_t ofd_vdevice_vty(void *m, ofdn_t p, struct domain *d)
{
    ofdn_t n;
    static const char pathfmt[] = "/vdevice/vty@%x";
    static const char name[] = "vty";
    static const char compatible[] = "hvterm1";
    static const char device_type[] = "serial";
    char path[sizeof (pathfmt) + 8 - 2];
    int client = 0;

    snprintf(path, sizeof (path), pathfmt, client);
    n = ofd_node_add(m, p, path, sizeof (path));

    if (n > 0) {
        u32 val32;

        val32 = client;
        ofd_prop_add(m, n, "name", name, sizeof (name));
        ofd_prop_add(m, n, "reg", &val32, sizeof (val32));
        ofd_prop_add(m, n, "compatible",
                     compatible, sizeof (compatible));
        ofd_prop_add(m, n, "device_type",
                     device_type, sizeof (device_type));
    }

    return n;
}
#endif

#ifdef PAPR_VDEVICE
static ofdn_t ofd_vdevice(void *m, struct domain *d)
{
    ofdn_t n;
    static const char path[] = "/vdevice";
    static const char name[] = "vdevice";
    static const char compatible[] = "IBM,vdevice";
    u32 val;

    n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));

    if (n > 0) {

        ofd_prop_add(m, n, "name", name, sizeof (name));
        val = 1;
        ofd_prop_add(m, n, "#address-cells", &val, sizeof (val));
        val = 0;
        ofd_prop_add(m, n, "#size-cells", &val, sizeof (val));
        ofd_prop_add(m, n, "compatible",
                     compatible, sizeof (compatible));
        ofd_prop_add(m, n, "device_type", name, sizeof (name));
        ofd_prop_add(m, n, "interupt-controller", NULL, 0);

#ifdef PAPR_VDEVICE
        ofdn_t r;

        /* add vty */
        r = ofd_vdevice_vty(m, n, d);
        printk("vdevice r: %x\n", r);
        n = r;
#endif
    }
    return n;
}
#endif

static ofdn_t ofd_openprom_props(void *m)
{
    static const char path[] = "/openprom";
    static const char vernum[] = "IBM,XenOF0.1";
    ofdn_t n;

    n = ofd_node_find(m, path);
    if (n == 0) {
        n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
        ofd_prop_add(m, n, "name",
                     &path[1], sizeof (path) - 1);
    }
    /* I want to override */
    ofd_prop_add(m, n, "model", vernum, sizeof(vernum));
    ofd_prop_add(m, n, "ibm,fw-vernum_encoded", vernum, sizeof(vernum));
    ofd_prop_add(m, n, "relative-addressing", NULL, 0);
    return n;

}

#ifdef PAPR_VTERM
static ofdn_t ofd_aliases_props(void *m)
{
    static const char path[] = "/aliases";
    static const char screen[] = "/vdevice/vty@0";
    ofdn_t n;

    n = ofd_node_find(m, path);
    if (n == 0) {
        n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
        ofd_prop_add(m, n, "name",
                     &path[1], sizeof (path) - 1);
    }
    ofd_prop_add(m, n, "screen", screen, sizeof(screen));
    return n;
}
#endif

static ofdn_t ofd_options_props(void *m)
{
    static const char path[] = "/options";
    static const char boot[] = "true";
    ofdn_t n;

    n = ofd_node_find(m, path);
    if (n == 0) {
        n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
        ofd_prop_add(m, n, "name",
                     &path[1], sizeof (path) - 1);
    }
    ofd_prop_add(m, n, "auto-boot?", boot, sizeof(boot));
    return n;
}

static ofdn_t ofd_cpus_props(void *m, struct domain *d)
{
    static const char path[] = "/cpus";
    static const char cpu[] = "cpu";
    u32 val = 1;
    ofdn_t n;
    ofdn_t c;
    static u32 ibm_pft_size[] = { 0x0, 0x0 };

    n = ofd_node_find(m, path);
    if (n == 0) {
        n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
        ofd_prop_add(m, n, "name",
                     &path[1], sizeof (path) - 1);
    }
    ofd_prop_add(m, n, "#address-cells", &val, sizeof(val));
    ofd_prop_add(m, n, "#size-cells", &val, sizeof(val));
    ofd_prop_add(m, n, "smp-enabled", NULL, 0);

#ifdef HV_EXPOSE_PERFORMANCE_MONITOR
    ofd_prop_add(m, n, "performance-monitor", NULL, 0);
#endif

    c = ofd_node_find_by_prop(m, n, "device_type", cpu, sizeof (cpu));
    if (ofd_boot_cpu == -1)
        ofd_boot_cpu = c;
    while (c > 0) {
        /* We do not use the OF tree to identify secondary processors
         * so we must prune them from the tree */
        if (c == ofd_boot_cpu) {
            ofdn_t p;

            ibm_pft_size[1] = d->arch.htab.log_num_ptes + LOG_PTE_SIZE;
            ofd_prop_add(m, c, "ibm,pft-size",
                         ibm_pft_size, sizeof (ibm_pft_size));

            /* get rid of non-standard properties */
            p = ofd_prop_find(m, c, "cpu#");
            if (p > 0) {
                ofd_prop_remove(m, c, p);
            }

            /* FIXME: Check the the "l2-cache" property who's
             * contents is an orphaned phandle? */
        } else
            ofd_node_prune(m, c);

        c = ofd_node_find_next(m, c);
    }

    return n;
}

#ifdef ADD_XICS
static ofdn_t ofd_xics_props(void *m)
{
    ofdn_t n;
    static const char path[] = "/interrupt-controller";
    static const char compat[] = "IBM,ppc-xicp";
    static const char model[] = "IBM, BoaC, PowerPC-PIC, 00";
    static const char dtype[] =
        "PowerPC-External-Interrupt-Presentation";
    /*
     * I don't think these are used for anything but linux wants
     * it.  I seems to describe some per processor location for
     * IPIs but that is a complete guess.
     */
    static const u32 reg[] = {
        0x000003e0, 0x0f000000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f001000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f002000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f003000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f004000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f005000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f006000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f007000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f008000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f009000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f00a000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f00b000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f00c000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f00d000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f00e000, 0x00000000, 0x00001000,
        0x000003e0, 0x0f00f000, 0x00000000, 0x00001000,
    };

    n = ofd_node_find(m, path);
    if (n == 0) {
        n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
        ofd_prop_add(m, n, "name",
                     &path[1], sizeof (path) - 1);
    }
    ofd_prop_add(m, n, "built-in", NULL, 0);
    ofd_prop_add(m, n, "compatible", compat, sizeof(compat));
    ofd_prop_add(m, n, "device_type", dtype, sizeof(dtype));
    ofd_prop_add(m, n, "model", model, sizeof(model));
    ofd_prop_add(m, n, "reg", reg, sizeof(reg));

    return n;
}
#endif

/*
 * Good things you can stick here:
 *   init=/bin/bash ip=dhcp root=/dev/hda2 ide=nodma 
 */
static char default_bootargs[] = ""; 

static ofdn_t ofd_chosen_props(void *m, const char *cmdline)
{
    ofdn_t n;
    ofdn_t p;
    static const char path[] = "/chosen";
    char bootargs[256];
    int bsz;
    int sz;
    int rm;

    n = ofd_node_find(m, path);
    if (n == 0) {
        n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
        ofd_prop_add(m, n, "name",
                     &path[1], sizeof (path) - 1);
    }

    strcpy(bootargs, cmdline);
    bsz = strlen(bootargs) + 1;
    rm = sizeof (bootargs) - bsz;

    if (default_bootargs != NULL) {
        sz = strlen(default_bootargs);
        if (sz > rm) {
            panic("default_bootargs is too big: 0x%x > 0x%x\n",
                  sz, rm);
        } else if (sz > 0) {
            memcpy(&bootargs[bsz - 1], default_bootargs, sz + 1);
            bsz += sz;
            rm -= sz;
        }
    }

    printk("DOM0 bootargs: %s\n", bootargs);
    ofd_prop_add(m, n, "bootargs", bootargs, bsz);

    ofd_prop_add(m, n, "bootpath", NULL, 0);

    printk("Remove /chosen/mmu, stub will replace\n");
    p = ofd_prop_find(m, n, "mmu");
    if (p > 0) {
        ofd_prop_remove(m, n, p);
    }

    return n;
}

#ifdef RTAS
static ofdn_t ofd_rtas_props(void *m)
{
    static const char path[] = "/rtas";
    static const char hypertas[] = "dummy";
    ofdn_t p;
    ofdn_t n;

    /* just enough to make linux think its on LPAR */

    p = ofd_node_find(m, "/");

    n = ofd_node_add(m, p, path, sizeof(path));
    ofd_prop_add(m, n, "name", &path[1], sizeof (path) - 1);
    ofd_prop_add(m, n, "ibm,hypertas-functions", hypertas, sizeof (hypertas));

    return n;
}
#endif

static ofdn_t ofd_xen_props(void *m, struct domain *d, start_info_t *si)
{
    ofdn_t n;
    static const char path[] = "/xen";
    static const char console[] = "/xen/console";

    n = ofd_node_add(m, OFD_ROOT, path, sizeof (path));
    if (n > 0) {
        char xen[256];
        int xl;
        u64 val[2];
        s32 dom_id;

        dom_id = d->domain_id;

        ofd_prop_add(m, n, "reg", &dom_id, sizeof (dom_id));
        ofd_prop_add(m, n, "name", &path[1], sizeof (path) - 1);

        xl = snprintf(xen, sizeof (xen), "Xen-%d.%d%s",
                xen_major_version(), xen_minor_version(), xen_extra_version());
        ASSERT(xl < sizeof (xen));
        ofd_prop_add(m, n, "version", xen, xl + 1);

        val[0] = (ulong)si - page_to_maddr(d->arch.rma_page);
        val[1] = PAGE_SIZE;
        ofd_prop_add(m, n, "start-info", val, sizeof (val));

        val[1] =  RMA_LAST_DOM0 * PAGE_SIZE;
        val[0] =  rma_size(d->arch.rma_order) - val[1];
        ofd_prop_add(m, n, "reserved", val, sizeof (val));

        /* tell dom0 that Xen depends on it to have power control */
        if (!rtas_entry)
            ofd_prop_add(m, n, "power-control", NULL, 0);

        /* tell dom0 where ranted pages go in the linear map */
        val[0] = cpu_foreign_map_order();
        val[1] = d->arch.foreign_mfn_count;
        ofd_prop_add(m, n, "foreign-map", val, sizeof (val));

        n = ofd_node_add(m, n, console, sizeof (console));
        if (n > 0) {
            val[0] = 0;
            ofd_prop_add(m, n, "interrupts", &val[0], sizeof (val[0]));
        }
    }
    return n;
}

int ofd_dom0_fixup(struct domain *d, ulong mem, start_info_t *si)
{
    void *m;
    const ofdn_t n = OFD_ROOT;
    ofdn_t r;

    m = (void *)mem;

#ifdef PAPR_VDEVICE
    printk("Add /vdevice\n");
    ofd_vdevice(m, d);

    printk("Add /aliases props\n");
    ofd_aliases_props(m);
#endif

    printk("Add /openprom props\n");
    ofd_openprom_props(m);

    printk("Add /options props\n");
    ofd_options_props(m);

    printk("Add /cpus props\n");
    ofd_cpus_props(m, d);

    printk("Add /chosen props\n");
    ofd_chosen_props(m, (char *)si->cmd_line);

    printk("fix /memory props\n");
    ofd_memory_props(m, d);

    printk("fix /xen props\n");
    ofd_xen_props(m, d, si);

    printk("Remove original /dart\n");
    ofd_prune_path(m, "/dart");

    printk("Remove original /rtas\n");
    ofd_prune_path(m, "/rtas");

#ifdef RTAS
    printk("Create a new RTAS with just enough stuff to convince "
           "Linux that its on LPAR\n");
    ofd_rtas_props(m);
#endif
#ifdef FIX_COMPAT 
    const char compat[] = "Hypervisor,Maple";
    r = ofd_prop_add(m, n, "compatible", compat, sizeof (compat));
    ASSERT( r > 0 );
#endif

    u32 did = d->domain_id;
    r = ofd_prop_add(m, n, "ibm,partition-no", &did, sizeof(did));
    ASSERT( r > 0 );

    const char d0[] = "dom0";
    r = ofd_prop_add(m, n, "ibm,partition-name", d0, sizeof (d0));
    ASSERT( r > 0 );


#ifdef DEBUG
    ofd_walk(m, __func__, OFD_ROOT, ofd_dump_props, OFD_DUMP_ALL);
#endif
    return 1;
}
