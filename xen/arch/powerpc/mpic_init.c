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
#include <asm/mpic.h>
#include <errno.h>
#include "mpic_init.h"
#include "oftree.h"
#include "of-devtree.h"

#undef DEBUG
#define CONFIG_SHARE_MPIC

#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

#define PANIC(fmt...) DBG(fmt)

static struct mpic *mpic;
static unsigned long opic_addr;
static unsigned int opic_flags;

/*
 * from OF_IEEE_1275
 *
 * pg 175, property "ranges"
 *
 * The number of integers in each size entry is determined by the
 * value of the #size-cells property of this node (the node in which
 * the ranges property appears) or 1 if the #size-cells property is
 * absent.
 *
 *
 * pg 177, property "reg"
 *
 * The number of integers in each size entry is determined by the
 * value of the "#size-cells" property in the parent node.  If the
 * parent node has no such property, the value is one.
 */
static unsigned long reg2(void *oft_p, ofdn_t c)
{
    int rc;
    /* the struct isa_reg_property is for a value of 2 for
     * #address-cells and a value of 1 for #size-cells (of the
     * parent).
     */
    struct isa_reg_property {
        u32 space;
        u32 address;
        u32 size;
    } isa_reg;

    rc = ofd_getprop(oft_p, c, "reg", &isa_reg, sizeof(isa_reg));

    DBG("%s: reg property address=0x%08x  size=0x%08x\n", __func__,
        isa_reg.address, isa_reg.size);
    return isa_reg.address;
}

static unsigned long reg1(void *oft_p, ofdn_t c)
{
    int rc;
    /* the struct reg_property32 is for a value of 1 for
     * #address-cells and a value of 1 for #size-cells.
     */
    struct reg_property32 {
        u32 address;
        u32 size;
    } reg;

    rc = ofd_getprop(oft_p, c, "reg", &reg, sizeof(reg));

    DBG("%s: reg property address=0x%08x  size=0x%08x\n", __func__,
        reg.address, reg.size);
    return reg.address;
}

static unsigned long find_reg_addr_from_node(void *oft_p, ofdn_t c)
{
    int p_len;
    unsigned long reg_addr = 0;
    u32 size_c = 1;
    u32 addr_c = 2;
    ofdn_t parent;

    if (c == OFD_ROOT) {
        parent = c;
    } else {
        parent = ofd_node_parent(oft_p, c);
    }

    p_len = ofd_getprop(oft_p, parent, "#size-cells", &size_c, sizeof(size_c));
    DBG("%s size is %d\n", __func__, size_c);

    p_len = ofd_getprop(oft_p, parent, "#address-cells", &addr_c,
                        sizeof(addr_c));
    DBG("%s address is %d\n", __func__, addr_c);

    if ( 1 != size_c ) {
        PANIC("Unsupported size for reg property\n");
    }
    
    if ( 1 == addr_c) {
        reg_addr = reg1(oft_p, c);
    } else if ( 2 == addr_c ) {
        reg_addr = reg2(oft_p, c);
    } else {
        PANIC("Unsupported address size for reg property\n");
    }
    DBG("%s: address 0x%lx\n", __func__, reg_addr);
    return reg_addr;
}

/*
 * from OF_IEEE_1275
 *
 * pg 175, property "ranges"
 * 
 * The ranges property value is a sequence of child-phys parent-phys
 * size specifications. Child-phys is an address, encoded as with
 * encode-phys, in the child address space. Parent-phys is an address
 * (likewise encoded as with encode-phys) in the parent address
 * space. Size is a list of integers, each encoded as with encode-int,
 * denoting the length of the child's address range.
 */
static unsigned long find_ranges_addr_from_node(void *oft_p, ofdn_t c)
{
    unsigned long ranges_addr = 0;
    int ranges_i;
    ofdn_t parent;
    u32 addr_c = 2;
    u32 ranges[64];
    int p_len;

    parent = ofd_node_parent(oft_p, c);
    parent = ofd_node_parent(oft_p, parent);

    p_len = ofd_getprop(oft_p, parent, "ranges", &ranges, sizeof(ranges));
    DBG("%s: ranges\n", __func__);
    int i; for (i=0; i<p_len; i++) {DBG("%08x ", ranges[i]);}
    DBG("\n");

    p_len = ofd_getprop(oft_p, parent, "#address-cells",
                        &addr_c, sizeof(addr_c));
    DBG("%s address is %d\n", __func__, addr_c);
    ranges_i = addr_c;  /* skip over the child address */
    
    DBG("%s address is %d\n", __func__, addr_c);
    switch (addr_c) {
    case 1: 
        ranges_addr = ranges[ranges_i];
        break;
    case 2:
        ranges_addr = (((u64)ranges[ranges_i]) << 32) |
            ranges[ranges_i + 1];
        break;
    case 3:  /* the G5 case, how to squeeze 96 bits into 64 */
        ranges_addr = (((u64)ranges[ranges_i+1]) << 32) |
            ranges[ranges_i + 2];
        break;
    case 4:
        ranges_addr = (((u64)ranges[ranges_i+2]) << 32) |
            ranges[ranges_i + 4];
        break;
    default:
        PANIC("#address-cells out of range\n");
        break;
    }
    
    DBG("%s: address 0x%lx\n", __func__, ranges_addr);
    return ranges_addr;
}

static unsigned long find_pic_address_from_node(void *oft_p, ofdn_t c)
{
    unsigned long reg_addr, range_addr, addr;

    /*
     * The address is the sum of the address in the reg property of this node
     * and the ranges property of the granparent node.
     */
    reg_addr = find_reg_addr_from_node(oft_p, c);
    range_addr = find_ranges_addr_from_node(oft_p, c);
    addr = reg_addr + range_addr;
    DBG("%s: address 0x%lx\n", __func__, addr);
    return addr;
}

static unsigned int find_pic_flags_from_node(void *oft_p, ofdn_t c)
{
    int be_len;
    unsigned int flags = 0;

    /* does it have the property big endian? */
    be_len = ofd_getprop(oft_p, c, "big_endian", NULL, 0);
    if (be_len >= 0) {
        DBG("%s: Big Endian found\n", __func__);
        flags |= MPIC_BIG_ENDIAN;
    }
    DBG("%s: flags 0x%x\n", __func__, flags);
    return flags;
}

static int find_mpic_simple_probe(void *oft_p)
{
    u32 addr_cells;
    int rc;
    u32 addr[2];

    rc = ofd_getprop(oft_p, OFD_ROOT, "#address-cells",
                     &addr_cells, sizeof(addr_cells));
    if ( rc < 0 ) {
        /* if the property does not exist use its default value, 2 */
        addr_cells = 2;
    }

    rc = ofd_getprop(oft_p, OFD_ROOT, "platform-open-pic", addr, sizeof(addr));
    if (rc < 0) {
        return rc;
    }

    opic_addr = addr[0];
    if (addr_cells == 2) {
        opic_addr <<= 32;
        opic_addr |= addr[1];
    }
    DBG("%s: found OpenPIC at: 0x%lx\n", __func__, opic_addr);
    /* we did not really find the pic device, only its address. 
     * We use big endian and broken u3 by default.
     */
    opic_flags |= MPIC_BIG_ENDIAN | MPIC_BROKEN_U3;
    return 0;
}

static int find_mpic_canonical_probe(void *oft_p)
{
    ofdn_t c;
    const char mpic_type[] = "open-pic";
    /* some paths are special and we cannot find the address
     * by the usual method */
    const char *excluded_paths[] = { "/interrupt-controller" };

    /*
     * Search through the OFD tree for all devices of type 'open_pic'.
     * We select the one without an 'interrupt' property.
     */
    c = ofd_node_find_by_prop(oft_p, OFD_ROOT, "device_type", mpic_type,
                              sizeof(mpic_type));
    while (c > 0) {
        int int_len;
        int good_mpic;
        const char * path = ofd_node_path(oft_p, c);

        good_mpic = 0;
        int_len = ofd_getprop(oft_p, c, "interrupts", NULL, 0);
        if (int_len < 0) {
            int i;

            /* there is no property interrupt.  This could be the pic */
            DBG("%s: potential OpenPIC in: %s\n", __func__, path);
            good_mpic = 1;

            for (i = 0; i < ARRAY_SIZE(excluded_paths) && good_mpic; i++) {
                const char *excluded_path = excluded_paths[i];
                if (!strncmp(path, excluded_path, strlen(excluded_path)))
                    good_mpic = 0;
            }
        }

        if (good_mpic) {
            DBG("%s: found OpenPIC in: %s\n", __func__, path);
            opic_addr = find_pic_address_from_node(oft_p, c);
            opic_flags = find_pic_flags_from_node(oft_p, c);
            return 0;
        }

        c = ofd_node_find_next(oft_p, c);
    }

    DBG("%s: Could not find a pic\n", __func__);
    return -1;
}

static int find_mpic(void)
{
    void *oft_p;
    int rc;

    opic_addr = (unsigned long)-1;
    opic_flags = 0;

    oft_p = (void *)oftree;
    rc = find_mpic_simple_probe(oft_p);

    if (rc < 0) {
        DBG("%s: Searching for pic ...\n", __func__);
        rc = find_mpic_canonical_probe(oft_p);
    }

    return rc;
}

#ifdef CONFIG_SHARE_MPIC
static struct hw_interrupt_type hc_irq;

static struct hw_interrupt_type *share_mpic(
    struct hw_interrupt_type *mpic_irq,
    struct hw_interrupt_type *xen_irq)
{
    hc_irq.startup = mpic_irq->startup;
    mpic_irq->startup = xen_irq->startup;

    hc_irq.enable = mpic_irq->enable;
    mpic_irq->enable = xen_irq->enable;

    hc_irq.disable = mpic_irq->disable;
    mpic_irq->disable = xen_irq->disable;

    hc_irq.shutdown = mpic_irq->shutdown;
    mpic_irq->shutdown = xen_irq->shutdown;

    hc_irq.ack = mpic_irq->ack;
    mpic_irq->ack = xen_irq->ack;

    hc_irq.end = mpic_irq->end;
    mpic_irq->end = xen_irq->end;

    hc_irq.set_affinity = mpic_irq->set_affinity;
    mpic_irq->set_affinity = xen_irq->set_affinity;

    return &hc_irq;
}

#else  /* CONFIG_SHARE_MPIC */

#define share_mpic(M,X) (M)

#endif

static unsigned int mpic_startup_ipi(unsigned int irq)
{
    mpic->hc_ipi.enable(irq);
    return 0;
}

int request_irq(unsigned int irq,
                irqreturn_t (*handler)(int, void *, struct cpu_user_regs *),
                unsigned long irqflags, const char * devname, void *dev_id)
{
    int retval;
    struct irqaction *action;
    void (*func)(int, void *, struct cpu_user_regs *);

    action = xmalloc(struct irqaction);
    if (!action) {
        BUG();
        return -ENOMEM;
    }

    /* Xen's handler prototype is slightly different than Linux's.  */
    func = (void (*)(int, void *, struct cpu_user_regs *))handler;

    action->handler = func;
    action->name = devname;
    action->dev_id = dev_id;

    retval = setup_irq(irq, action);
    if (retval) {
        BUG();
        xfree(action);
    }

    return retval;
}

struct hw_interrupt_type *xen_mpic_init(struct hw_interrupt_type *xen_irq)
{
    unsigned int isu_size;
    unsigned int irq_offset;
    unsigned int irq_count;
    unsigned int ipi_offset;
    unsigned char *senses;
    unsigned int senses_count;
    struct hw_interrupt_type *hit;

    printk("%s: start\n", __func__);

    io_apic_irqs = ~0;  /* all IRQs go through IOAPIC */
	irq_vector[0] = FIRST_DEVICE_VECTOR;
	vector_irq[FIRST_DEVICE_VECTOR] = 0;

    isu_size = 0;
    irq_offset = 0;
    irq_count = 128;
    ipi_offset = 128;
    senses = NULL;
    senses_count = 0;

    if (find_mpic()) {
        printk("%s: ERROR: Could not find open pic.\n", __func__);
        return NULL;
    }

    mpic = mpic_alloc(opic_addr,
                      opic_flags | MPIC_PRIMARY | MPIC_WANTS_RESET,
                      isu_size, irq_offset, irq_count,
                      ipi_offset, senses, senses_count, "Xen-U3-MPIC");

    BUG_ON(mpic == NULL);
    mpic_init(mpic);

    hit = share_mpic(&mpic->hc_irq, xen_irq);

    printk("%s: success\n", __func__);

    mpic->hc_ipi.ack = xen_irq->ack;
    mpic->hc_ipi.startup = mpic_startup_ipi;
    mpic_request_ipis();

    return hit;
}

int xen_mpic_get_irq(struct cpu_user_regs *regs)
{
    BUG_ON(mpic == NULL);

	return mpic_get_one_irq(mpic, regs);
}
