/*
 * hvm.c: Common hardware virtual machine abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/shadow.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/shadow.h>
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>
#endif
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/hvm/hvm_info_table.h>

int hvm_enabled = 0;
int hvm_switch_on = 0;

unsigned int opt_hvm_debug_level = 0;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs;

static void hvm_map_io_shared_page(struct domain *d)
{
    int i;
    unsigned char e820_map_nr;
    struct e820entry *e820entry;
    unsigned char *p;
    unsigned long mpfn;
    unsigned long gpfn = 0;

    local_flush_tlb_pge();

    mpfn = get_mfn_from_pfn(E820_MAP_PAGE >> PAGE_SHIFT);
    if (mpfn == INVALID_MFN) {
        printk("Can not find E820 memory map page for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page(mpfn);
    if (p == NULL) {
        printk("Can not map E820 memory map page for HVM domain.\n");
        domain_crash_synchronous();
    }

    e820_map_nr = *(p + E820_MAP_NR_OFFSET);
    e820entry = (struct e820entry *)(p + E820_MAP_OFFSET);

    for ( i = 0; i < e820_map_nr; i++ )
    {
        if (e820entry[i].type == E820_SHARED_PAGE)
        {
            gpfn = (e820entry[i].addr >> PAGE_SHIFT);
            break;
        }
    }

    if ( gpfn == 0 ) {
        printk("Can not get io request shared page"
               " from E820 memory map for HVM domain.\n");
        unmap_domain_page(p);
        domain_crash_synchronous();
    }
    unmap_domain_page(p);

    /* Initialise shared page */
    mpfn = get_mfn_from_pfn(gpfn);
    if (mpfn == INVALID_MFN) {
        printk("Can not find io request shared page for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page_global(mpfn);
    if (p == NULL) {
        printk("Can not map io request shared page for HVM domain.\n");
        domain_crash_synchronous();
    }
    d->arch.hvm_domain.shared_page_va = (unsigned long)p;

    HVM_DBG_LOG(DBG_LEVEL_1, "eport: %x\n", iopacket_port(d));

    clear_bit(iopacket_port(d),
              &d->shared_info->evtchn_mask[0]);
}

static int validate_hvm_info(struct hvm_info_table *t)
{
    char signature[] = "HVM INFO";
    uint8_t *ptr = (uint8_t *)t;
    uint8_t sum = 0;
    int i;

    /* strncmp(t->signature, "HVM INFO", 8) */
    for ( i = 0; i < 8; i++ ) {
        if ( signature[i] != t->signature[i] ) {
            printk("Bad hvm info signature\n");
            return 0;
        }
    }

    for ( i = 0; i < t->length; i++ )
        sum += ptr[i];

    return (sum == 0);
}

static void hvm_get_info(struct domain *d)
{
    unsigned char *p;
    unsigned long mpfn;
    struct hvm_info_table *t;

    mpfn = get_mfn_from_pfn(HVM_INFO_PFN);
    if ( mpfn == INVALID_MFN ) {
        printk("Can not get info page mfn for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page(mpfn);
    if ( p == NULL ) {
        printk("Can not map info page for HVM domain.\n");
        domain_crash_synchronous();
    }

    t = (struct hvm_info_table *)(p + HVM_INFO_OFFSET);

    if ( validate_hvm_info(t) ) {
        d->arch.hvm_domain.nr_vcpus = t->nr_vcpus;
        d->arch.hvm_domain.apic_enabled = t->apic_enabled;
    } else {
        printk("Bad hvm info table\n");
        d->arch.hvm_domain.nr_vcpus = 1;
        d->arch.hvm_domain.apic_enabled = 0;
    }

    unmap_domain_page(p);
}

void hvm_setup_platform(struct domain* d)
{
    struct hvm_domain *platform;

    if (!(HVM_DOMAIN(current) && (current->vcpu_id == 0)))
        return;

    hvm_map_io_shared_page(d);
    hvm_get_info(d);

    platform = &d->arch.hvm_domain;
    pic_init(&platform->vpic, pic_irq_request, &platform->interrupt_request);
    register_pic_io_hook();

    if ( hvm_apic_support(d) ) {
        spin_lock_init(&d->arch.hvm_domain.round_robin_lock);
        hvm_vioapic_init(d);
    }
}

void pic_irq_request(int *interrupt_request, int level)
{
    if (level)
        *interrupt_request = 1;
    else
        *interrupt_request = 0;
}

void hvm_pic_assist(struct vcpu *v)
{
    global_iodata_t *spg;
    u16   *virq_line, irqs;
    struct hvm_virpic *pic = &v->domain->arch.hvm_domain.vpic;
    
    spg = &get_sp(v->domain)->sp_global;
    virq_line  = &spg->pic_clear_irr;
    if ( *virq_line ) {
        do {
            irqs = *(volatile u16*)virq_line;
        } while ( (u16)cmpxchg(virq_line,irqs, 0) != irqs );
        do_pic_irqs_clear(pic, irqs);
    }
    virq_line  = &spg->pic_irr;
    if ( *virq_line ) {
        do {
            irqs = *(volatile u16*)virq_line;
        } while ( (u16)cmpxchg(virq_line,irqs, 0) != irqs );
        do_pic_irqs(pic, irqs);
    }
}

int cpu_get_interrupt(struct vcpu *v, int *type)
{
    int intno;
    struct hvm_virpic *s = &v->domain->arch.hvm_domain.vpic;

    if ( (intno = cpu_get_apic_interrupt(v, type)) != -1 ) {
        /* set irq request if a PIC irq is still pending */
        /* XXX: improve that */
        pic_update_irq(s);
        return intno;
    }
    /* read the irq from the PIC */
    if ( (intno = cpu_get_pic_interrupt(v, type)) != -1 )
        return intno;

    return -1;
}

/*
 * Copy from/to guest virtual.
 */
int
hvm_copy(void *buf, unsigned long vaddr, int size, int dir)
{
    unsigned long gpa, mfn;
    char *addr;
    int count;

    while (size > 0) {
        count = PAGE_SIZE - (vaddr & ~PAGE_MASK);
        if (count > size)
            count = size;

        if (hvm_paging_enabled(current)) {
            gpa = gva_to_gpa(vaddr);
            mfn = get_mfn_from_pfn(gpa >> PAGE_SHIFT);
        } else
            mfn = get_mfn_from_pfn(vaddr >> PAGE_SHIFT);
        if (mfn == INVALID_MFN)
            return 0;

        addr = (char *)map_domain_page(mfn) + (vaddr & ~PAGE_MASK);

        if (dir == HVM_COPY_IN)
            memcpy(buf, addr, count);
        else
            memcpy(addr, buf, count);

        unmap_domain_page(addr);

        vaddr += count;
        buf += count;
        size -= count;
    }

    return 1;
}

/*
 * HVM specific printbuf. Mostly used for hvmloader chit-chat.
 */
void hvm_print_line(struct vcpu *v, const char c)
{
    int *index = &v->domain->arch.hvm_domain.pbuf_index;
    char *pbuf = v->domain->arch.hvm_domain.pbuf;

    if (*index == HVM_PBUF_SIZE-2 || c == '\n') {
        if (*index == HVM_PBUF_SIZE-2)
	    pbuf[(*index)++] = c;
        pbuf[*index] = '\0';
        printk("(GUEST: %u) %s\n", v->domain->domain_id, pbuf);
	*index = 0;
    } else
	pbuf[(*index)++] = c;
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

