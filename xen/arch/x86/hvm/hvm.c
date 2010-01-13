/*
 * hvm.c: Common hardware virtual machine abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
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
#include <xen/ctype.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/paging.h>
#include <asm/shadow.h>
#include <asm/hap.h>
#include <asm/current.h>
#include <asm/e820.h>
#include <asm/io.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/i387.h>
#include <asm/traps.h>
#include <asm/mc146818rtc.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/hvm/trace.h>
#include <asm/mtrr.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/version.h>
#include <public/memory.h>

int hvm_enabled __read_mostly;

unsigned int opt_hvm_debug_level __read_mostly;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs __read_mostly;

/* I/O permission bitmap is globally shared by all HVM guests. */
unsigned long __attribute__ ((__section__ (".bss.page_aligned")))
    hvm_io_bitmap[3*PAGE_SIZE/BYTES_PER_LONG];

void hvm_enable(struct hvm_function_table *fns)
{
    extern int hvm_port80_allowed;

    BUG_ON(hvm_enabled);
    printk("HVM: %s enabled\n", fns->name);

    /*
     * Allow direct access to the PC debug ports 0x80 and 0xed (they are
     * often used for I/O delays, but the vmexits simply slow things down).
     */
    memset(hvm_io_bitmap, ~0, sizeof(hvm_io_bitmap));
    if ( hvm_port80_allowed )
        __clear_bit(0x80, hvm_io_bitmap);
    __clear_bit(0xed, hvm_io_bitmap);

    hvm_funcs   = *fns;
    hvm_enabled = 1;

    if ( hvm_funcs.hap_supported )
        printk("HVM: Hardware Assisted Paging detected.\n");
}

/*
 * Need to re-inject a given event? We avoid re-injecting software exceptions
 * and interrupts because the faulting/trapping instruction can simply be
 * re-executed (neither VMX nor SVM update RIP when they VMEXIT during
 * INT3/INTO/INTn).
 */
int hvm_event_needs_reinjection(uint8_t type, uint8_t vector)
{
    switch ( type )
    {
    case X86_EVENTTYPE_EXT_INTR:
    case X86_EVENTTYPE_NMI:
        return 1;
    case X86_EVENTTYPE_HW_EXCEPTION:
        /*
         * SVM uses type 3 ("HW Exception") for #OF and #BP. We explicitly
         * check for these vectors, as they are really SW Exceptions. SVM has
         * not updated RIP to point after the trapping instruction (INT3/INTO).
         */
        return (vector != 3) && (vector != 4);
    default:
        /* Software exceptions/interrupts can be re-executed (e.g., INT n). */
        break;
    }
    return 0;
}

/*
 * Combine two hardware exceptions: @vec2 was raised during delivery of @vec1.
 * This means we can assume that @vec2 is contributory or a page fault.
 */
uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2)
{
    /* Exception during double-fault delivery always causes a triple fault. */
    if ( vec1 == TRAP_double_fault )
    {
        hvm_triple_fault();
        return TRAP_double_fault; /* dummy return */
    }

    /* Exception during page-fault delivery always causes a double fault. */
    if ( vec1 == TRAP_page_fault )
        return TRAP_double_fault;

    /* Discard the first exception if it's benign or if we now have a #PF. */
    if ( !((1u << vec1) & 0x7c01u) || (vec2 == TRAP_page_fault) )
        return vec2;

    /* Cannot combine the exceptions: double fault. */
    return TRAP_double_fault;
}

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        hvm_funcs.set_rdtsc_exiting(v, enable);
}

int hvm_gtsc_need_scale(struct domain *d)
{
    uint32_t gtsc_mhz, htsc_mhz;

    if ( d->arch.vtsc )
        return 0;

    gtsc_mhz = d->arch.hvm_domain.gtsc_khz / 1000;
    htsc_mhz = (uint32_t)cpu_khz / 1000;

    d->arch.hvm_domain.tsc_scaled = (gtsc_mhz && (gtsc_mhz != htsc_mhz));
    return d->arch.hvm_domain.tsc_scaled;
}

static u64 hvm_h2g_scale_tsc(struct vcpu *v, u64 host_tsc)
{
    uint32_t gtsc_khz, htsc_khz;

    if ( !v->domain->arch.hvm_domain.tsc_scaled )
        return host_tsc;

    htsc_khz = cpu_khz;
    gtsc_khz = v->domain->arch.hvm_domain.gtsc_khz;
    return muldiv64(host_tsc, gtsc_khz, htsc_khz);
}

void hvm_set_guest_tsc(struct vcpu *v, u64 guest_tsc)
{
    uint64_t tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time(v);
    }
    else
    {
        rdtscll(tsc);
        tsc = hvm_h2g_scale_tsc(v, tsc);
    }

    v->arch.hvm_vcpu.cache_tsc_offset = guest_tsc - tsc;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);
}

u64 hvm_get_guest_tsc(struct vcpu *v)
{
    uint64_t tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time(v);
        v->domain->arch.vtsc_kerncount++;
    }
    else
    {
        rdtscll(tsc);
        tsc = hvm_h2g_scale_tsc(v, tsc);
    }

    return tsc + v->arch.hvm_vcpu.cache_tsc_offset;
}

void hvm_migrate_timers(struct vcpu *v)
{
    rtc_migrate_timers(v);
    pt_migrate(v);
}

void hvm_migrate_pirqs(struct vcpu *v)
{
    int pirq, irq;
    struct irq_desc *desc;
    struct domain *d = v->domain;
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    
    if ( !iommu_enabled || (hvm_irq_dpci == NULL) )
       return;

    spin_lock(&d->event_lock);
    for ( pirq = find_first_bit(hvm_irq_dpci->mapping, d->nr_pirqs);
          pirq < d->nr_pirqs;
          pirq = find_next_bit(hvm_irq_dpci->mapping, d->nr_pirqs, pirq + 1) )
    {
        if ( !(hvm_irq_dpci->mirq[pirq].flags & HVM_IRQ_DPCI_MACH_MSI) ||
               (hvm_irq_dpci->mirq[pirq].gmsi.dest_vcpu_id != v->vcpu_id) )
            continue;
        desc = domain_spin_lock_irq_desc(v->domain, pirq, NULL);
        if (!desc)
            continue;
        irq = desc - irq_desc;
        ASSERT(MSI_IRQ(irq));
        irq_set_affinity(irq, *cpumask_of(v->processor));
        spin_unlock_irq(&desc->lock);
    }
    spin_unlock(&d->event_lock);
}

void hvm_do_resume(struct vcpu *v)
{
    ioreq_t *p;

    pt_restore_timer(v);

    /* NB. Optimised for common case (p->state == STATE_IOREQ_NONE). */
    p = get_ioreq(v);
    while ( p->state != STATE_IOREQ_NONE )
    {
        switch ( p->state )
        {
        case STATE_IORESP_READY: /* IORESP_READY -> NONE */
            hvm_io_assist();
            break;
        case STATE_IOREQ_READY:  /* IOREQ_{READY,INPROCESS} -> IORESP_READY */
        case STATE_IOREQ_INPROCESS:
            wait_on_xen_event_channel(v->arch.hvm_vcpu.xen_port,
                                      (p->state != STATE_IOREQ_READY) &&
                                      (p->state != STATE_IOREQ_INPROCESS));
            break;
        default:
            gdprintk(XENLOG_ERR, "Weird HVM iorequest state %d.\n", p->state);
            domain_crash(v->domain);
            return; /* bail */
        }
    }
}

static void hvm_init_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    memset(iorp, 0, sizeof(*iorp));
    spin_lock_init(&iorp->lock);
    domain_pause(d);
}

static void hvm_destroy_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    spin_lock(&iorp->lock);

    ASSERT(d->is_dying);

    if ( iorp->va != NULL )
    {
        unmap_domain_page_global(iorp->va);
        put_page_and_type(iorp->page);
        iorp->va = NULL;
    }

    spin_unlock(&iorp->lock);
}

static int hvm_set_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp, unsigned long gmfn)
{
    struct page_info *page;
    p2m_type_t p2mt;
    unsigned long mfn;
    void *va;

    mfn = mfn_x(gfn_to_mfn_unshare(d, gmfn, &p2mt, 0));
    if ( !p2m_is_ram(p2mt) )
        return -EINVAL;
    if ( p2m_is_paging(p2mt) )
    {
        p2m_mem_paging_populate(d, gmfn);
        return -ENOENT;
    }
    if ( p2m_is_shared(p2mt) )
        return -ENOENT;
    ASSERT(mfn_valid(mfn));

    page = mfn_to_page(mfn);
    if ( !get_page_and_type(page, d, PGT_writable_page) )
        return -EINVAL;

    va = map_domain_page_global(mfn);
    if ( va == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    spin_lock(&iorp->lock);

    if ( (iorp->va != NULL) || d->is_dying )
    {
        spin_unlock(&iorp->lock);
        unmap_domain_page_global(va);
        put_page_and_type(mfn_to_page(mfn));
        return -EINVAL;
    }

    iorp->va = va;
    iorp->page = page;

    spin_unlock(&iorp->lock);

    domain_unpause(d);

    return 0;
}

static int hvm_print_line(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val)
{
    struct vcpu *curr = current;
    struct hvm_domain *hd = &curr->domain->arch.hvm_domain;
    char c = *val;

    BUG_ON(bytes != 1);

    /* Accept only printable characters, newline, and horizontal tab. */
    if ( !isprint(c) && (c != '\n') && (c != '\t') )
        return X86EMUL_OKAY;

    spin_lock(&hd->pbuf_lock);
    hd->pbuf[hd->pbuf_idx++] = c;
    if ( (hd->pbuf_idx == (sizeof(hd->pbuf) - 2)) || (c == '\n') )
    {
        if ( c != '\n' )
            hd->pbuf[hd->pbuf_idx++] = '\n';
        hd->pbuf[hd->pbuf_idx] = '\0';
        printk(XENLOG_G_DEBUG "HVM%u: %s", curr->domain->domain_id, hd->pbuf);
        hd->pbuf_idx = 0;
    }
    spin_unlock(&hd->pbuf_lock);

    return X86EMUL_OKAY;
}

int hvm_domain_initialise(struct domain *d)
{
    int rc;

    if ( !hvm_enabled )
    {
        gdprintk(XENLOG_WARNING, "Attempt to create a HVM guest "
                 "on a non-VT/AMDV platform.\n");
        return -EINVAL;
    }

    spin_lock_init(&d->arch.hvm_domain.pbuf_lock);
    spin_lock_init(&d->arch.hvm_domain.irq_lock);
    spin_lock_init(&d->arch.hvm_domain.uc_lock);

    INIT_LIST_HEAD(&d->arch.hvm_domain.msixtbl_list);
    spin_lock_init(&d->arch.hvm_domain.msixtbl_list_lock);

    hvm_init_guest_time(d);

    d->arch.hvm_domain.params[HVM_PARAM_HPET_ENABLED] = 1;

    hvm_init_cacheattr_region_list(d);

    rc = paging_enable(d, PG_refcounts|PG_translate|PG_external);
    if ( rc != 0 )
        goto fail1;

    vpic_init(d);

    rc = vioapic_init(d);
    if ( rc != 0 )
        goto fail1;

    stdvga_init(d);

    rtc_init(d);

    hvm_init_ioreq_page(d, &d->arch.hvm_domain.ioreq);
    hvm_init_ioreq_page(d, &d->arch.hvm_domain.buf_ioreq);

    register_portio_handler(d, 0xe9, 1, hvm_print_line);

    rc = hvm_funcs.domain_initialise(d);
    if ( rc != 0 )
        goto fail2;

    return 0;

 fail2:
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);
 fail1:
    hvm_destroy_cacheattr_region_list(d);
    return rc;
}

extern void msixtbl_pt_cleanup(struct domain *d);

void hvm_domain_relinquish_resources(struct domain *d)
{
    hvm_destroy_ioreq_page(d, &d->arch.hvm_domain.ioreq);
    hvm_destroy_ioreq_page(d, &d->arch.hvm_domain.buf_ioreq);

    msixtbl_pt_cleanup(d);

    /* Stop all asynchronous timer actions. */
    rtc_deinit(d);
    if ( d->vcpu != NULL && d->vcpu[0] != NULL )
    {
        pit_deinit(d);
        pmtimer_deinit(d);
        hpet_deinit(d);
    }
}

void hvm_domain_destroy(struct domain *d)
{
    hvm_funcs.domain_destroy(d);
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);
    hvm_destroy_cacheattr_region_list(d);
}

static int hvm_save_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;
    struct vcpu_guest_context *vc;

    for_each_vcpu ( d, v )
    {
        /* We don't need to save state for a vcpu that is down; the restore 
         * code will leave it down if there is nothing saved. */
        if ( test_bit(_VPF_down, &v->pause_flags) ) 
            continue;

        /* Architecture-specific vmcs/vmcb bits */
        hvm_funcs.save_cpu_ctxt(v, &ctxt);

        ctxt.msr_tsc_aux = hvm_msr_tsc_aux(v);

        hvm_get_segment_register(v, x86_seg_idtr, &seg);
        ctxt.idtr_limit = seg.limit;
        ctxt.idtr_base = seg.base;

        hvm_get_segment_register(v, x86_seg_gdtr, &seg);
        ctxt.gdtr_limit = seg.limit;
        ctxt.gdtr_base = seg.base;

        hvm_get_segment_register(v, x86_seg_cs, &seg);
        ctxt.cs_sel = seg.sel;
        ctxt.cs_limit = seg.limit;
        ctxt.cs_base = seg.base;
        ctxt.cs_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_ds, &seg);
        ctxt.ds_sel = seg.sel;
        ctxt.ds_limit = seg.limit;
        ctxt.ds_base = seg.base;
        ctxt.ds_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_es, &seg);
        ctxt.es_sel = seg.sel;
        ctxt.es_limit = seg.limit;
        ctxt.es_base = seg.base;
        ctxt.es_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_ss, &seg);
        ctxt.ss_sel = seg.sel;
        ctxt.ss_limit = seg.limit;
        ctxt.ss_base = seg.base;
        ctxt.ss_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_fs, &seg);
        ctxt.fs_sel = seg.sel;
        ctxt.fs_limit = seg.limit;
        ctxt.fs_base = seg.base;
        ctxt.fs_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_gs, &seg);
        ctxt.gs_sel = seg.sel;
        ctxt.gs_limit = seg.limit;
        ctxt.gs_base = seg.base;
        ctxt.gs_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_tr, &seg);
        ctxt.tr_sel = seg.sel;
        ctxt.tr_limit = seg.limit;
        ctxt.tr_base = seg.base;
        ctxt.tr_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_ldtr, &seg);
        ctxt.ldtr_sel = seg.sel;
        ctxt.ldtr_limit = seg.limit;
        ctxt.ldtr_base = seg.base;
        ctxt.ldtr_arbytes = seg.attr.bytes;

        vc = &v->arch.guest_context;

        if ( v->fpu_initialised )
            memcpy(ctxt.fpu_regs, &vc->fpu_ctxt, sizeof(ctxt.fpu_regs));
        else 
            memset(ctxt.fpu_regs, 0, sizeof(ctxt.fpu_regs));

        ctxt.rax = vc->user_regs.eax;
        ctxt.rbx = vc->user_regs.ebx;
        ctxt.rcx = vc->user_regs.ecx;
        ctxt.rdx = vc->user_regs.edx;
        ctxt.rbp = vc->user_regs.ebp;
        ctxt.rsi = vc->user_regs.esi;
        ctxt.rdi = vc->user_regs.edi;
        ctxt.rsp = vc->user_regs.esp;
        ctxt.rip = vc->user_regs.eip;
        ctxt.rflags = vc->user_regs.eflags;
#ifdef __x86_64__
        ctxt.r8  = vc->user_regs.r8;
        ctxt.r9  = vc->user_regs.r9;
        ctxt.r10 = vc->user_regs.r10;
        ctxt.r11 = vc->user_regs.r11;
        ctxt.r12 = vc->user_regs.r12;
        ctxt.r13 = vc->user_regs.r13;
        ctxt.r14 = vc->user_regs.r14;
        ctxt.r15 = vc->user_regs.r15;
#endif
        ctxt.dr0 = vc->debugreg[0];
        ctxt.dr1 = vc->debugreg[1];
        ctxt.dr2 = vc->debugreg[2];
        ctxt.dr3 = vc->debugreg[3];
        ctxt.dr6 = vc->debugreg[6];
        ctxt.dr7 = vc->debugreg[7];

        if ( hvm_save_entry(CPU, v->vcpu_id, h, &ctxt) != 0 )
            return 1; 
    }
    return 0;
}

static int hvm_load_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid, rc;
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;
    struct vcpu_guest_context *vc;

    /* Which vcpu is this? */
    vcpuid = hvm_load_instance(h);
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        gdprintk(XENLOG_ERR, "HVM restore: domain has no vcpu %u\n", vcpuid);
        return -EINVAL;
    }
    vc = &v->arch.guest_context;

    /* Need to init this vcpu before loading its contents */
    rc = 0;
    domain_lock(d);
    if ( !v->is_initialised )
        rc = boot_vcpu(d, vcpuid, vc);
    domain_unlock(d);
    if ( rc != 0 )
        return rc;

    if ( hvm_load_entry(CPU, h, &ctxt) != 0 ) 
        return -EINVAL;

    /* Sanity check some control registers. */
    if ( (ctxt.cr0 & HVM_CR0_GUEST_RESERVED_BITS) ||
         !(ctxt.cr0 & X86_CR0_ET) ||
         ((ctxt.cr0 & (X86_CR0_PE|X86_CR0_PG)) == X86_CR0_PG) )
    {
        gdprintk(XENLOG_ERR, "HVM restore: bad CR0 0x%"PRIx64"\n",
                 ctxt.cr0);
        return -EINVAL;
    }

    if ( ctxt.cr4 & HVM_CR4_GUEST_RESERVED_BITS )
    {
        gdprintk(XENLOG_ERR, "HVM restore: bad CR4 0x%"PRIx64"\n",
                 ctxt.cr4);
        return -EINVAL;
    }

    if ( (ctxt.msr_efer & ~(EFER_FFXSE | EFER_LME | EFER_LMA |
                            EFER_NX | EFER_SCE)) ||
         ((sizeof(long) != 8) && (ctxt.msr_efer & EFER_LME)) ||
         (!cpu_has_nx && (ctxt.msr_efer & EFER_NX)) ||
         (!cpu_has_syscall && (ctxt.msr_efer & EFER_SCE)) ||
         (!cpu_has_ffxsr && (ctxt.msr_efer & EFER_FFXSE)) ||
         ((ctxt.msr_efer & (EFER_LME|EFER_LMA)) == EFER_LMA) )
    {
        gdprintk(XENLOG_ERR, "HVM restore: bad EFER 0x%"PRIx64"\n",
                 ctxt.msr_efer);
        return -EINVAL;
    }

    /* Older Xen versions used to save the segment arbytes directly 
     * from the VMCS on Intel hosts.  Detect this and rearrange them
     * into the struct segment_register format. */
#define UNFOLD_ARBYTES(_r)                          \
    if ( (_r & 0xf000) && !(_r & 0x0f00) )          \
        _r = ((_r & 0xff) | ((_r >> 4) & 0xf00))
    UNFOLD_ARBYTES(ctxt.cs_arbytes);
    UNFOLD_ARBYTES(ctxt.ds_arbytes);
    UNFOLD_ARBYTES(ctxt.es_arbytes);
    UNFOLD_ARBYTES(ctxt.fs_arbytes);
    UNFOLD_ARBYTES(ctxt.gs_arbytes);
    UNFOLD_ARBYTES(ctxt.ss_arbytes);
    UNFOLD_ARBYTES(ctxt.tr_arbytes);
    UNFOLD_ARBYTES(ctxt.ldtr_arbytes);
#undef UNFOLD_ARBYTES

    /* Architecture-specific vmcs/vmcb bits */
    if ( hvm_funcs.load_cpu_ctxt(v, &ctxt) < 0 )
        return -EINVAL;

    v->arch.hvm_vcpu.msr_tsc_aux = ctxt.msr_tsc_aux;

    seg.limit = ctxt.idtr_limit;
    seg.base = ctxt.idtr_base;
    hvm_set_segment_register(v, x86_seg_idtr, &seg);

    seg.limit = ctxt.gdtr_limit;
    seg.base = ctxt.gdtr_base;
    hvm_set_segment_register(v, x86_seg_gdtr, &seg);

    seg.sel = ctxt.cs_sel;
    seg.limit = ctxt.cs_limit;
    seg.base = ctxt.cs_base;
    seg.attr.bytes = ctxt.cs_arbytes;
    hvm_set_segment_register(v, x86_seg_cs, &seg);

    seg.sel = ctxt.ds_sel;
    seg.limit = ctxt.ds_limit;
    seg.base = ctxt.ds_base;
    seg.attr.bytes = ctxt.ds_arbytes;
    hvm_set_segment_register(v, x86_seg_ds, &seg);

    seg.sel = ctxt.es_sel;
    seg.limit = ctxt.es_limit;
    seg.base = ctxt.es_base;
    seg.attr.bytes = ctxt.es_arbytes;
    hvm_set_segment_register(v, x86_seg_es, &seg);

    seg.sel = ctxt.ss_sel;
    seg.limit = ctxt.ss_limit;
    seg.base = ctxt.ss_base;
    seg.attr.bytes = ctxt.ss_arbytes;
    hvm_set_segment_register(v, x86_seg_ss, &seg);

    seg.sel = ctxt.fs_sel;
    seg.limit = ctxt.fs_limit;
    seg.base = ctxt.fs_base;
    seg.attr.bytes = ctxt.fs_arbytes;
    hvm_set_segment_register(v, x86_seg_fs, &seg);

    seg.sel = ctxt.gs_sel;
    seg.limit = ctxt.gs_limit;
    seg.base = ctxt.gs_base;
    seg.attr.bytes = ctxt.gs_arbytes;
    hvm_set_segment_register(v, x86_seg_gs, &seg);

    seg.sel = ctxt.tr_sel;
    seg.limit = ctxt.tr_limit;
    seg.base = ctxt.tr_base;
    seg.attr.bytes = ctxt.tr_arbytes;
    hvm_set_segment_register(v, x86_seg_tr, &seg);

    seg.sel = ctxt.ldtr_sel;
    seg.limit = ctxt.ldtr_limit;
    seg.base = ctxt.ldtr_base;
    seg.attr.bytes = ctxt.ldtr_arbytes;
    hvm_set_segment_register(v, x86_seg_ldtr, &seg);

    memcpy(&vc->fpu_ctxt, ctxt.fpu_regs, sizeof(ctxt.fpu_regs));

    vc->user_regs.eax = ctxt.rax;
    vc->user_regs.ebx = ctxt.rbx;
    vc->user_regs.ecx = ctxt.rcx;
    vc->user_regs.edx = ctxt.rdx;
    vc->user_regs.ebp = ctxt.rbp;
    vc->user_regs.esi = ctxt.rsi;
    vc->user_regs.edi = ctxt.rdi;
    vc->user_regs.esp = ctxt.rsp;
    vc->user_regs.eip = ctxt.rip;
    vc->user_regs.eflags = ctxt.rflags | 2;
#ifdef __x86_64__
    vc->user_regs.r8  = ctxt.r8; 
    vc->user_regs.r9  = ctxt.r9; 
    vc->user_regs.r10 = ctxt.r10;
    vc->user_regs.r11 = ctxt.r11;
    vc->user_regs.r12 = ctxt.r12;
    vc->user_regs.r13 = ctxt.r13;
    vc->user_regs.r14 = ctxt.r14;
    vc->user_regs.r15 = ctxt.r15;
#endif
    vc->debugreg[0] = ctxt.dr0;
    vc->debugreg[1] = ctxt.dr1;
    vc->debugreg[2] = ctxt.dr2;
    vc->debugreg[3] = ctxt.dr3;
    vc->debugreg[6] = ctxt.dr6;
    vc->debugreg[7] = ctxt.dr7;

    vc->flags = VGCF_online;
    v->fpu_initialised = 1;

    /* Auxiliary processors should be woken immediately. */
    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);
    vcpu_wake(v);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(CPU, hvm_save_cpu_ctxt, hvm_load_cpu_ctxt,
                          1, HVMSR_PER_VCPU);

int hvm_vcpu_initialise(struct vcpu *v)
{
    int rc;

    hvm_asid_flush_vcpu(v);

    if ( cpu_has_xsave )
    {
        /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
        void *xsave_area = _xmalloc(xsave_cntxt_size, 64);
        if ( xsave_area == NULL )
            return -ENOMEM;

        xsave_init_save_area(xsave_area);
        v->arch.hvm_vcpu.xsave_area = xsave_area;
        v->arch.hvm_vcpu.xfeature_mask = XSTATE_FP_SSE;
    }

    if ( (rc = vlapic_init(v)) != 0 )
        goto fail1;

    if ( (rc = hvm_funcs.vcpu_initialise(v)) != 0 )
        goto fail2;

    /* Create ioreq event channel. */
    rc = alloc_unbound_xen_event_channel(v, 0);
    if ( rc < 0 )
        goto fail3;

    /* Register ioreq event channel. */
    v->arch.hvm_vcpu.xen_port = rc;
    spin_lock(&v->domain->arch.hvm_domain.ioreq.lock);
    if ( v->domain->arch.hvm_domain.ioreq.va != NULL )
        get_ioreq(v)->vp_eport = v->arch.hvm_vcpu.xen_port;
    spin_unlock(&v->domain->arch.hvm_domain.ioreq.lock);

    spin_lock_init(&v->arch.hvm_vcpu.tm_lock);
    INIT_LIST_HEAD(&v->arch.hvm_vcpu.tm_list);

    rc = hvm_vcpu_cacheattr_init(v);
    if ( rc != 0 )
        goto fail3;

    tasklet_init(&v->arch.hvm_vcpu.assert_evtchn_irq_tasklet,
                 (void(*)(unsigned long))hvm_assert_evtchn_irq,
                 (unsigned long)v);

    v->arch.guest_context.user_regs.eflags = 2;

    if ( v->vcpu_id == 0 )
    {
        /* NB. All these really belong in hvm_domain_initialise(). */
        pit_init(v, cpu_khz);
        pmtimer_init(v);
        hpet_init(v);
 
        /* Init guest TSC to start from zero. */
        hvm_set_guest_tsc(v, 0);

        /* Can start up without SIPI-SIPI or setvcpucontext domctl. */
        v->is_initialised = 1;
        clear_bit(_VPF_down, &v->pause_flags);
    }

    return 0;

 fail3:
    hvm_funcs.vcpu_destroy(v);
 fail2:
    vlapic_destroy(v);
 fail1:
    return rc;
}

void hvm_vcpu_destroy(struct vcpu *v)
{
    tasklet_kill(&v->arch.hvm_vcpu.assert_evtchn_irq_tasklet);
    hvm_vcpu_cacheattr_destroy(v);
    vlapic_destroy(v);
    hvm_funcs.vcpu_destroy(v);
    xfree(v->arch.hvm_vcpu.xsave_area);

    /* Event channel is already freed by evtchn_destroy(). */
    /*free_xen_event_channel(v, v->arch.hvm_vcpu.xen_port);*/
}

void hvm_vcpu_down(struct vcpu *v)
{
    struct domain *d = v->domain;
    int online_count = 0;

    /* Doesn't halt us immediately, but we'll never return to guest context. */
    set_bit(_VPF_down, &v->pause_flags);
    vcpu_sleep_nosync(v);

    /* Any other VCPUs online? ... */
    domain_lock(d);
    for_each_vcpu ( d, v )
        if ( !test_bit(_VPF_down, &v->pause_flags) )
            online_count++;
    domain_unlock(d);

    /* ... Shut down the domain if not. */
    if ( online_count == 0 )
    {
        gdprintk(XENLOG_INFO, "All CPUs offline -- powering off.\n");
        domain_shutdown(d, SHUTDOWN_poweroff);
    }
}

bool_t hvm_send_assist_req(struct vcpu *v)
{
    ioreq_t *p;

    if ( unlikely(!vcpu_start_shutdown_deferral(v)) )
        return 0; /* implicitly bins the i/o operation */

    p = get_ioreq(v);
    if ( unlikely(p->state != STATE_IOREQ_NONE) )
    {
        /* This indicates a bug in the device model. Crash the domain. */
        gdprintk(XENLOG_ERR, "Device model set bad IO state %d.\n", p->state);
        domain_crash(v->domain);
        return 0;
    }

    prepare_wait_on_xen_event_channel(v->arch.hvm_vcpu.xen_port);

    /*
     * Following happens /after/ blocking and setting up ioreq contents.
     * prepare_wait_on_xen_event_channel() is an implicit barrier.
     */
    p->state = STATE_IOREQ_READY;
    notify_via_xen_event_channel(v->arch.hvm_vcpu.xen_port);

    return 1;
}

void hvm_hlt(unsigned long rflags)
{
    struct vcpu *curr = current;

    if ( hvm_event_pending(curr) )
        return;

    /*
     * If we halt with interrupts disabled, that's a pretty sure sign that we
     * want to shut down. In a real processor, NMIs are the only way to break
     * out of this.
     */
    if ( unlikely(!(rflags & X86_EFLAGS_IF)) )
        return hvm_vcpu_down(curr);

    do_sched_op_compat(SCHEDOP_block, 0);

    HVMTRACE_1D(HLT, /* pending = */ vcpu_runnable(curr));
}

void hvm_triple_fault(void)
{
    struct vcpu *v = current;
    gdprintk(XENLOG_INFO, "Triple fault on VCPU%d - "
             "invoking HVM system reset.\n", v->vcpu_id);
    domain_shutdown(v->domain, SHUTDOWN_reboot);
}

bool_t hvm_hap_nested_page_fault(unsigned long gfn)
{
    p2m_type_t p2mt;
    mfn_t mfn;

    mfn = gfn_to_mfn_type_current(gfn, &p2mt, p2m_guest);

    /*
     * If this GFN is emulated MMIO or marked as read-only, pass the fault
     * to the mmio handler.
     */
    if ( (p2mt == p2m_mmio_dm) || (p2mt == p2m_ram_ro) )
    {
        if ( !handle_mmio() )
            hvm_inject_exception(TRAP_gp_fault, 0, 0);
        return 1;
    }

    /* Check if the page has been paged out */
    if ( p2m_is_paged(p2mt) || (p2mt == p2m_ram_paging_out) )
        p2m_mem_paging_populate(current->domain, gfn);

    /* Mem sharing: unshare the page and try again */
    if ( p2mt == p2m_ram_shared )
    {
        mem_sharing_unshare_page(current->domain, gfn, 0);
        return 1;
    }
 
    /* Spurious fault? PoD and log-dirty also take this path. */
    if ( p2m_is_ram(p2mt) )
    {
        paging_mark_dirty(current->domain, mfn_x(mfn));
        p2m_change_type(current->domain, gfn, p2m_ram_logdirty, p2m_ram_rw);
        return 1;
    }

    /* Shouldn't happen: Maybe the guest was writing to a r/o grant mapping? */
    if ( p2mt == p2m_grant_map_ro )
    {
        gdprintk(XENLOG_WARNING,
                 "trying to write to read-only grant mapping\n");
        hvm_inject_exception(TRAP_gp_fault, 0, 0);
        return 1;
    }

    return 0;
}

int hvm_set_efer(uint64_t value)
{
    struct vcpu *v = current;

    value &= ~EFER_LMA;

    if ( (value & ~(EFER_FFXSE | EFER_LME | EFER_NX | EFER_SCE)) ||
         ((sizeof(long) != 8) && (value & EFER_LME)) ||
         (!cpu_has_nx && (value & EFER_NX)) ||
         (!cpu_has_syscall && (value & EFER_SCE)) ||
         (!cpu_has_ffxsr && (value & EFER_FFXSE)) )
    {
        gdprintk(XENLOG_WARNING, "Trying to set reserved bit in "
                 "EFER: %"PRIx64"\n", value);
        hvm_inject_exception(TRAP_gp_fault, 0, 0);
        return X86EMUL_EXCEPTION;
    }

    if ( ((value ^ v->arch.hvm_vcpu.guest_efer) & EFER_LME) &&
         hvm_paging_enabled(v) )
    {
        gdprintk(XENLOG_WARNING,
                 "Trying to change EFER.LME with paging enabled\n");
        hvm_inject_exception(TRAP_gp_fault, 0, 0);
        return X86EMUL_EXCEPTION;
    }

    value |= v->arch.hvm_vcpu.guest_efer & EFER_LMA;
    v->arch.hvm_vcpu.guest_efer = value;
    hvm_update_guest_efer(v);

    return X86EMUL_OKAY;
}

extern void shadow_blow_tables_per_domain(struct domain *d);

/* Exit UC mode only if all VCPUs agree on MTRR/PAT and are not in no_fill. */
static bool_t domain_exit_uc_mode(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct vcpu *vs;

    for_each_vcpu ( d, vs )
    {
        if ( (vs == v) || !vs->is_initialised )
            continue;
        if ( (vs->arch.hvm_vcpu.cache_mode == NO_FILL_CACHE_MODE) ||
             mtrr_pat_not_equal(vs, v) )
            return 0;
    }

    return 1;
}

static void local_flush_cache(void *info)
{
    wbinvd();
}

static void hvm_set_uc_mode(struct vcpu *v, bool_t is_in_uc_mode)
{
    v->domain->arch.hvm_domain.is_in_uc_mode = is_in_uc_mode;
    shadow_blow_tables_per_domain(v->domain);
    if ( hvm_funcs.set_uc_mode )
        return hvm_funcs.set_uc_mode(v);
}

int hvm_set_cr0(unsigned long value)
{
    struct vcpu *v = current;
    p2m_type_t p2mt;
    unsigned long gfn, mfn, old_value = v->arch.hvm_vcpu.guest_cr[0];

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx", value);

    if ( (u32)value != value )
    {
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Guest attempts to set upper 32 bits in CR0: %lx",
                    value);
        goto gpf;
    }

    value &= ~HVM_CR0_GUEST_RESERVED_BITS;

    /* ET is reserved and should be always be 1. */
    value |= X86_CR0_ET;

    if ( (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PG )
        goto gpf;

    if ( (value & X86_CR0_PG) && !(old_value & X86_CR0_PG) )
    {
        if ( v->arch.hvm_vcpu.guest_efer & EFER_LME )
        {
            if ( !(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PAE) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enable");
                goto gpf;
            }
            HVM_DBG_LOG(DBG_LEVEL_1, "Enabling long mode");
            v->arch.hvm_vcpu.guest_efer |= EFER_LMA;
            hvm_update_guest_efer(v);
        }

        if ( !paging_mode_hap(v->domain) )
        {
            /* The guest CR3 must be pointing to the guest physical. */
            gfn = v->arch.hvm_vcpu.guest_cr[3]>>PAGE_SHIFT;
            mfn = mfn_x(gfn_to_mfn_current(gfn, &p2mt));
            if ( !p2m_is_ram(p2mt) || !mfn_valid(mfn) ||
                 !get_page(mfn_to_page(mfn), v->domain))
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value = %lx (mfn=%lx)\n",
                         v->arch.hvm_vcpu.guest_cr[3], mfn);
                domain_crash(v->domain);
                return X86EMUL_UNHANDLEABLE;
            }

            /* Now arch.guest_table points to machine physical. */
            v->arch.guest_table = pagetable_from_pfn(mfn);

            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                        v->arch.hvm_vcpu.guest_cr[3], mfn);
        }
    }
    else if ( !(value & X86_CR0_PG) && (old_value & X86_CR0_PG) )
    {
        /* When CR0.PG is cleared, LMA is cleared immediately. */
        if ( hvm_long_mode_enabled(v) )
        {
            v->arch.hvm_vcpu.guest_efer &= ~EFER_LMA;
            hvm_update_guest_efer(v);
        }

        if ( !paging_mode_hap(v->domain) )
        {
            put_page(pagetable_get_page(v->arch.guest_table));
            v->arch.guest_table = pagetable_null();
        }
    }

    if ( has_arch_pdevs(v->domain) )
    {
        if ( (value & X86_CR0_CD) && !(value & X86_CR0_NW) )
        {
            /* Entering no fill cache mode. */
            spin_lock(&v->domain->arch.hvm_domain.uc_lock);
            v->arch.hvm_vcpu.cache_mode = NO_FILL_CACHE_MODE;

            if ( !v->domain->arch.hvm_domain.is_in_uc_mode )
            {
                /* Flush physical caches. */
                on_each_cpu(local_flush_cache, NULL, 1);
                hvm_set_uc_mode(v, 1);
            }
            spin_unlock(&v->domain->arch.hvm_domain.uc_lock);
        }
        else if ( !(value & (X86_CR0_CD | X86_CR0_NW)) &&
                  (v->arch.hvm_vcpu.cache_mode == NO_FILL_CACHE_MODE) )
        {
            /* Exit from no fill cache mode. */
            spin_lock(&v->domain->arch.hvm_domain.uc_lock);
            v->arch.hvm_vcpu.cache_mode = NORMAL_CACHE_MODE;

            if ( domain_exit_uc_mode(v) )
                hvm_set_uc_mode(v, 0);

            spin_unlock(&v->domain->arch.hvm_domain.uc_lock);
        }
    }

    v->arch.hvm_vcpu.guest_cr[0] = value;
    hvm_update_guest_cr(v, 0);

    if ( (value ^ old_value) & X86_CR0_PG )
        paging_update_paging_modes(v);

    return X86EMUL_OKAY;

 gpf:
    hvm_inject_exception(TRAP_gp_fault, 0, 0);
    return X86EMUL_EXCEPTION;
}

int hvm_set_cr3(unsigned long value)
{
    unsigned long mfn;
    p2m_type_t p2mt;
    struct vcpu *v = current;

    if ( hvm_paging_enabled(v) && !paging_mode_hap(v->domain) &&
         (value != v->arch.hvm_vcpu.guest_cr[3]) )
    {
        /* Shadow-mode CR3 change. Check PDBR and update refcounts. */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
        mfn = mfn_x(gfn_to_mfn_current(value >> PAGE_SHIFT, &p2mt));
        if ( !p2m_is_ram(p2mt) || !mfn_valid(mfn) ||
             !get_page(mfn_to_page(mfn), v->domain) )
              goto bad_cr3;

        put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_from_pfn(mfn);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx", value);
    }

    v->arch.hvm_vcpu.guest_cr[3] = value;
    paging_update_cr3(v);
    return X86EMUL_OKAY;

 bad_cr3:
    gdprintk(XENLOG_ERR, "Invalid CR3\n");
    domain_crash(v->domain);
    return X86EMUL_UNHANDLEABLE;
}

int hvm_set_cr4(unsigned long value)
{
    struct vcpu *v = current;
    unsigned long old_cr;

    if ( value & HVM_CR4_GUEST_RESERVED_BITS )
    {
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Guest attempts to set reserved bit in CR4: %lx",
                    value);
        goto gpf;
    }

    if ( !(value & X86_CR4_PAE) && hvm_long_mode_enabled(v) )
    {
        HVM_DBG_LOG(DBG_LEVEL_1, "Guest cleared CR4.PAE while "
                    "EFER.LMA is set");
        goto gpf;
    }

    old_cr = v->arch.hvm_vcpu.guest_cr[4];
    v->arch.hvm_vcpu.guest_cr[4] = value;
    hvm_update_guest_cr(v, 4);

    /* Modifying CR4.{PSE,PAE,PGE} invalidates all TLB entries, inc. Global. */
    if ( (old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE) )
        paging_update_paging_modes(v);

    return X86EMUL_OKAY;

 gpf:
    hvm_inject_exception(TRAP_gp_fault, 0, 0);
    return X86EMUL_EXCEPTION;
}

int hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    unsigned int addr_size,
    unsigned long *linear_addr)
{
    unsigned long addr = offset;
    uint32_t last_byte;

    if ( !(current->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) )
    {
        /*
         * REAL MODE: Don't bother with segment access checks.
         * Certain of them are not done in native real mode anyway.
         */
        addr = (uint32_t)(addr + reg->base);
    }
    else if ( addr_size != 64 )
    {
        /*
         * COMPATIBILITY MODE: Apply segment checks and add base.
         */

        switch ( access_type )
        {
        case hvm_access_read:
            if ( (reg->attr.fields.type & 0xa) == 0x8 )
                goto gpf; /* execute-only code segment */
            break;
        case hvm_access_write:
            if ( (reg->attr.fields.type & 0xa) != 0x2 )
                goto gpf; /* not a writable data segment */
            break;
        default:
            break;
        }

        last_byte = offset + bytes - 1;

        /* Is this a grows-down data segment? Special limit check if so. */
        if ( (reg->attr.fields.type & 0xc) == 0x4 )
        {
            /* Is upper limit 0xFFFF or 0xFFFFFFFF? */
            if ( !reg->attr.fields.db )
                last_byte = (uint16_t)last_byte;

            /* Check first byte and last byte against respective bounds. */
            if ( (offset <= reg->limit) || (last_byte < offset) )
                goto gpf;
        }
        else if ( (last_byte > reg->limit) || (last_byte < offset) )
            goto gpf; /* last byte is beyond limit or wraps 0xFFFFFFFF */

        /*
         * Hardware truncates to 32 bits in compatibility mode.
         * It does not truncate to 16 bits in 16-bit address-size mode.
         */
        addr = (uint32_t)(addr + reg->base);
    }
    else
    {
        /*
         * LONG MODE: FS and GS add segment base. Addresses must be canonical.
         */

        if ( (seg == x86_seg_fs) || (seg == x86_seg_gs) )
            addr += reg->base;

        if ( !is_canonical_address(addr) )
            goto gpf;
    }

    *linear_addr = addr;
    return 1;

 gpf:
    return 0;
}

static void *hvm_map_entry(unsigned long va)
{
    unsigned long gfn, mfn;
    p2m_type_t p2mt;
    uint32_t pfec;

    if ( ((va & ~PAGE_MASK) + 8) > PAGE_SIZE )
    {
        gdprintk(XENLOG_ERR, "Descriptor table entry "
                 "straddles page boundary\n");
        domain_crash(current->domain);
        return NULL;
    }

    /* We're mapping on behalf of the segment-load logic, which might
     * write the accessed flags in the descriptors (in 32-bit mode), but
     * we still treat it as a kernel-mode read (i.e. no access checks). */
    pfec = PFEC_page_present;
    gfn = paging_gva_to_gfn(current, va, &pfec);
    if ( pfec == PFEC_page_paged || pfec == PFEC_page_shared )
        return NULL;
    mfn = mfn_x(gfn_to_mfn_unshare(current->domain, gfn, &p2mt, 0));
    if ( p2m_is_paging(p2mt) )
    {
        p2m_mem_paging_populate(current->domain, gfn);
        return NULL;
    }
    if ( p2m_is_shared(p2mt) )
        return NULL;
    if ( !p2m_is_ram(p2mt) )
    {
        gdprintk(XENLOG_ERR, "Failed to look up descriptor table entry\n");
        domain_crash(current->domain);
        return NULL;
    }

    ASSERT(mfn_valid(mfn));

    paging_mark_dirty(current->domain, mfn);

    return (char *)map_domain_page(mfn) + (va & ~PAGE_MASK);
}

static void hvm_unmap_entry(void *p)
{
    if ( p )
        unmap_domain_page(p);
}

static int hvm_load_segment_selector(
    enum x86_segment seg, uint16_t sel)
{
    struct segment_register desctab, cs, segr;
    struct desc_struct *pdesc, desc;
    u8 dpl, rpl, cpl;
    int fault_type = TRAP_invalid_tss;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct vcpu *v = current;

    if ( regs->eflags & X86_EFLAGS_VM )
    {
        segr.sel = sel;
        segr.base = (uint32_t)sel << 4;
        segr.limit = 0xffffu;
        segr.attr.bytes = 0xf3;
        hvm_set_segment_register(v, seg, &segr);
        return 0;
    }

    /* NULL selector? */
    if ( (sel & 0xfffc) == 0 )
    {
        if ( (seg == x86_seg_cs) || (seg == x86_seg_ss) )
            goto fail;
        memset(&segr, 0, sizeof(segr));
        hvm_set_segment_register(v, seg, &segr);
        return 0;
    }

    /* LDT descriptor must be in the GDT. */
    if ( (seg == x86_seg_ldtr) && (sel & 4) )
        goto fail;

    hvm_get_segment_register(v, x86_seg_cs, &cs);
    hvm_get_segment_register(
        v, (sel & 4) ? x86_seg_ldtr : x86_seg_gdtr, &desctab);

    /* Check against descriptor table limit. */
    if ( ((sel & 0xfff8) + 7) > desctab.limit )
        goto fail;

    pdesc = hvm_map_entry(desctab.base + (sel & 0xfff8));
    if ( pdesc == NULL )
        goto hvm_map_fail;

    do {
        desc = *pdesc;

        /* Segment present in memory? */
        if ( !(desc.b & (1u<<15)) )
        {
            fault_type = TRAP_no_segment;
            goto unmap_and_fail;
        }

        /* LDT descriptor is a system segment. All others are code/data. */
        if ( (desc.b & (1u<<12)) == ((seg == x86_seg_ldtr) << 12) )
            goto unmap_and_fail;

        dpl = (desc.b >> 13) & 3;
        rpl = sel & 3;
        cpl = cs.sel & 3;

        switch ( seg )
        {
        case x86_seg_cs:
            /* Code segment? */
            if ( !(desc.b & (1u<<11)) )
                goto unmap_and_fail;
            /* Non-conforming segment: check DPL against RPL. */
            if ( ((desc.b & (6u<<9)) != 6) && (dpl != rpl) )
                goto unmap_and_fail;
            break;
        case x86_seg_ss:
            /* Writable data segment? */
            if ( (desc.b & (5u<<9)) != (1u<<9) )
                goto unmap_and_fail;
            if ( (dpl != cpl) || (dpl != rpl) )
                goto unmap_and_fail;
            break;
        case x86_seg_ldtr:
            /* LDT system segment? */
            if ( (desc.b & (15u<<8)) != (2u<<8) )
                goto unmap_and_fail;
            goto skip_accessed_flag;
        default:
            /* Readable code or data segment? */
            if ( (desc.b & (5u<<9)) == (4u<<9) )
                goto unmap_and_fail;
            /* Non-conforming segment: check DPL against RPL and CPL. */
            if ( ((desc.b & (6u<<9)) != 6) && ((dpl < cpl) || (dpl < rpl)) )
                goto unmap_and_fail;
            break;
        }
    } while ( !(desc.b & 0x100) && /* Ensure Accessed flag is set */
              (cmpxchg(&pdesc->b, desc.b, desc.b | 0x100) != desc.b) );

    /* Force the Accessed flag in our local copy. */
    desc.b |= 0x100;

 skip_accessed_flag:
    hvm_unmap_entry(pdesc);

    segr.base = (((desc.b <<  0) & 0xff000000u) |
                 ((desc.b << 16) & 0x00ff0000u) |
                 ((desc.a >> 16) & 0x0000ffffu));
    segr.attr.bytes = (((desc.b >>  8) & 0x00ffu) |
                       ((desc.b >> 12) & 0x0f00u));
    segr.limit = (desc.b & 0x000f0000u) | (desc.a & 0x0000ffffu);
    if ( segr.attr.fields.g )
        segr.limit = (segr.limit << 12) | 0xfffu;
    segr.sel = sel;
    hvm_set_segment_register(v, seg, &segr);

    return 0;

 unmap_and_fail:
    hvm_unmap_entry(pdesc);
 fail:
    hvm_inject_exception(fault_type, sel & 0xfffc, 0);
 hvm_map_fail:
    return 1;
}

void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode)
{
    struct vcpu *v = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct segment_register gdt, tr, prev_tr, segr;
    struct desc_struct *optss_desc = NULL, *nptss_desc = NULL, tss_desc;
    unsigned long eflags;
    int exn_raised, rc;
    struct {
        u16 back_link,__blh;
        u32 esp0;
        u16 ss0, _0;
        u32 esp1;
        u16 ss1, _1;
        u32 esp2;
        u16 ss2, _2;
        u32 cr3, eip, eflags, eax, ecx, edx, ebx, esp, ebp, esi, edi;
        u16 es, _3, cs, _4, ss, _5, ds, _6, fs, _7, gs, _8, ldt, _9;
        u16 trace, iomap;
    } tss = { 0 };

    hvm_get_segment_register(v, x86_seg_gdtr, &gdt);
    hvm_get_segment_register(v, x86_seg_tr, &prev_tr);

    if ( ((tss_sel & 0xfff8) + 7) > gdt.limit )
    {
        hvm_inject_exception((taskswitch_reason == TSW_iret) ?
                             TRAP_invalid_tss : TRAP_gp_fault,
                             tss_sel & 0xfff8, 0);
        goto out;
    }

    optss_desc = hvm_map_entry(gdt.base + (prev_tr.sel & 0xfff8));
    if ( optss_desc == NULL )
        goto out;

    nptss_desc = hvm_map_entry(gdt.base + (tss_sel & 0xfff8));
    if ( nptss_desc == NULL )
        goto out;

    tss_desc = *nptss_desc;
    tr.sel = tss_sel;
    tr.base = (((tss_desc.b <<  0) & 0xff000000u) |
               ((tss_desc.b << 16) & 0x00ff0000u) |
               ((tss_desc.a >> 16) & 0x0000ffffu));
    tr.attr.bytes = (((tss_desc.b >>  8) & 0x00ffu) |
                     ((tss_desc.b >> 12) & 0x0f00u));
    tr.limit = (tss_desc.b & 0x000f0000u) | (tss_desc.a & 0x0000ffffu);
    if ( tr.attr.fields.g )
        tr.limit = (tr.limit << 12) | 0xfffu;

    if ( !tr.attr.fields.p )
    {
        hvm_inject_exception(TRAP_no_segment, tss_sel & 0xfff8, 0);
        goto out;
    }

    if ( tr.attr.fields.type != ((taskswitch_reason == TSW_iret) ? 0xb : 0x9) )
    {
        hvm_inject_exception(
            (taskswitch_reason == TSW_iret) ? TRAP_invalid_tss : TRAP_gp_fault,
            tss_sel & 0xfff8, 0);
        goto out;
    }

    if ( tr.limit < (sizeof(tss)-1) )
    {
        hvm_inject_exception(TRAP_invalid_tss, tss_sel & 0xfff8, 0);
        goto out;
    }

    rc = hvm_copy_from_guest_virt(
        &tss, prev_tr.base, sizeof(tss), PFEC_page_present);
    if ( rc == HVMCOPY_bad_gva_to_gfn )
        goto out;
    if ( rc == HVMCOPY_gfn_paged_out )
        goto out;
    if ( rc == HVMCOPY_gfn_shared )
        goto out;

    eflags = regs->eflags;
    if ( taskswitch_reason == TSW_iret )
        eflags &= ~X86_EFLAGS_NT;

    tss.cr3    = v->arch.hvm_vcpu.guest_cr[3];
    tss.eip    = regs->eip;
    tss.eflags = eflags;
    tss.eax    = regs->eax;
    tss.ecx    = regs->ecx;
    tss.edx    = regs->edx;
    tss.ebx    = regs->ebx;
    tss.esp    = regs->esp;
    tss.ebp    = regs->ebp;
    tss.esi    = regs->esi;
    tss.edi    = regs->edi;

    hvm_get_segment_register(v, x86_seg_es, &segr);
    tss.es = segr.sel;
    hvm_get_segment_register(v, x86_seg_cs, &segr);
    tss.cs = segr.sel;
    hvm_get_segment_register(v, x86_seg_ss, &segr);
    tss.ss = segr.sel;
    hvm_get_segment_register(v, x86_seg_ds, &segr);
    tss.ds = segr.sel;
    hvm_get_segment_register(v, x86_seg_fs, &segr);
    tss.fs = segr.sel;
    hvm_get_segment_register(v, x86_seg_gs, &segr);
    tss.gs = segr.sel;
    hvm_get_segment_register(v, x86_seg_ldtr, &segr);
    tss.ldt = segr.sel;

    rc = hvm_copy_to_guest_virt(
        prev_tr.base, &tss, sizeof(tss), PFEC_page_present);
    if ( rc == HVMCOPY_bad_gva_to_gfn )
        goto out;
    if ( rc == HVMCOPY_gfn_paged_out )
        goto out;
    if ( rc == HVMCOPY_gfn_shared )
        goto out;

    rc = hvm_copy_from_guest_virt(
        &tss, tr.base, sizeof(tss), PFEC_page_present);
    if ( rc == HVMCOPY_bad_gva_to_gfn )
        goto out;
    if ( rc == HVMCOPY_gfn_paged_out )
        goto out;
    /* Note: this could be optimised, if the callee functions knew we want RO
     * access */
    if ( rc == HVMCOPY_gfn_shared )
        goto out;


    if ( hvm_set_cr3(tss.cr3) )
        goto out;

    regs->eip    = tss.eip;
    regs->eflags = tss.eflags | 2;
    regs->eax    = tss.eax;
    regs->ecx    = tss.ecx;
    regs->edx    = tss.edx;
    regs->ebx    = tss.ebx;
    regs->esp    = tss.esp;
    regs->ebp    = tss.ebp;
    regs->esi    = tss.esi;
    regs->edi    = tss.edi;

    if ( (taskswitch_reason == TSW_call_or_int) )
    {
        regs->eflags |= X86_EFLAGS_NT;
        tss.back_link = prev_tr.sel;
    }

    exn_raised = 0;
    if ( hvm_load_segment_selector(x86_seg_ldtr, tss.ldt) ||
         hvm_load_segment_selector(x86_seg_es, tss.es) ||
         hvm_load_segment_selector(x86_seg_cs, tss.cs) ||
         hvm_load_segment_selector(x86_seg_ss, tss.ss) ||
         hvm_load_segment_selector(x86_seg_ds, tss.ds) ||
         hvm_load_segment_selector(x86_seg_fs, tss.fs) ||
         hvm_load_segment_selector(x86_seg_gs, tss.gs) )
        exn_raised = 1;

    rc = hvm_copy_to_guest_virt(
        tr.base, &tss, sizeof(tss), PFEC_page_present);
    if ( rc == HVMCOPY_bad_gva_to_gfn )
        exn_raised = 1;
    if ( rc == HVMCOPY_gfn_paged_out )
        goto out;
    if ( rc == HVMCOPY_gfn_shared )
        goto out;

    if ( (tss.trace & 1) && !exn_raised )
        hvm_inject_exception(TRAP_debug, tss_sel & 0xfff8, 0);

    tr.attr.fields.type = 0xb; /* busy 32-bit tss */
    hvm_set_segment_register(v, x86_seg_tr, &tr);

    v->arch.hvm_vcpu.guest_cr[0] |= X86_CR0_TS;
    hvm_update_guest_cr(v, 0);

    if ( (taskswitch_reason == TSW_iret) ||
         (taskswitch_reason == TSW_jmp) )
        clear_bit(41, optss_desc); /* clear B flag of old task */

    if ( taskswitch_reason != TSW_iret )
        set_bit(41, nptss_desc); /* set B flag of new task */

    if ( errcode >= 0 )
    {
        struct segment_register reg;
        unsigned long linear_addr;
        regs->esp -= 4;
        hvm_get_segment_register(current, x86_seg_ss, &reg);
        /* Todo: do not ignore access faults here. */
        if ( hvm_virtual_to_linear_addr(x86_seg_ss, &reg, regs->esp,
                                        4, hvm_access_write, 32,
                                        &linear_addr) )
            hvm_copy_to_guest_virt_nofault(linear_addr, &errcode, 4, 0);
    }

 out:
    hvm_unmap_entry(optss_desc);
    hvm_unmap_entry(nptss_desc);
}

#define HVMCOPY_from_guest (0u<<0)
#define HVMCOPY_to_guest   (1u<<0)
#define HVMCOPY_no_fault   (0u<<1)
#define HVMCOPY_fault      (1u<<1)
#define HVMCOPY_phys       (0u<<2)
#define HVMCOPY_virt       (1u<<2)
static enum hvm_copy_result __hvm_copy(
    void *buf, paddr_t addr, int size, unsigned int flags, uint32_t pfec)
{
    struct vcpu *curr = current;
    unsigned long gfn, mfn;
    p2m_type_t p2mt;
    char *p;
    int count, todo = size;

    while ( todo > 0 )
    {
        count = min_t(int, PAGE_SIZE - (addr & ~PAGE_MASK), todo);

        if ( flags & HVMCOPY_virt )
        {
            gfn = paging_gva_to_gfn(curr, addr, &pfec);
            if ( gfn == INVALID_GFN )
            {
                if ( pfec == PFEC_page_paged )
                    return HVMCOPY_gfn_paged_out;
                if ( pfec == PFEC_page_shared )
                    return HVMCOPY_gfn_shared;
                if ( flags & HVMCOPY_fault )
                    hvm_inject_exception(TRAP_page_fault, pfec, addr);
                return HVMCOPY_bad_gva_to_gfn;
            }
        }
        else
        {
            gfn = addr >> PAGE_SHIFT;
        }

        mfn = mfn_x(gfn_to_mfn_unshare(current->domain, gfn, &p2mt, 0));

        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(curr->domain, gfn);
            return HVMCOPY_gfn_paged_out;
        }
        if ( p2m_is_shared(p2mt) )
            return HVMCOPY_gfn_shared;
        if ( p2m_is_grant(p2mt) )
            return HVMCOPY_unhandleable;
        if ( !p2m_is_ram(p2mt) )
            return HVMCOPY_bad_gfn_to_mfn;
        ASSERT(mfn_valid(mfn));

        p = (char *)map_domain_page(mfn) + (addr & ~PAGE_MASK);

        if ( flags & HVMCOPY_to_guest )
        {
            if ( p2mt == p2m_ram_ro )
            {
                static unsigned long lastpage;
                if ( xchg(&lastpage, gfn) != gfn )
                    gdprintk(XENLOG_DEBUG, "guest attempted write to read-only"
                             " memory page. gfn=%#lx, mfn=%#lx\n",
                             gfn, mfn);
            }
            else
            {
                memcpy(p, buf, count);
                paging_mark_dirty(curr->domain, mfn);
            }
        }
        else
        {
            memcpy(buf, p, count);
        }

        unmap_domain_page(p);

        addr += count;
        buf  += count;
        todo -= count;
    }

    return HVMCOPY_okay;
}

enum hvm_copy_result hvm_copy_to_guest_phys(
    paddr_t paddr, void *buf, int size)
{
    return __hvm_copy(buf, paddr, size,
                      HVMCOPY_to_guest | HVMCOPY_fault | HVMCOPY_phys,
                      0);
}

enum hvm_copy_result hvm_copy_from_guest_phys(
    void *buf, paddr_t paddr, int size)
{
    return __hvm_copy(buf, paddr, size,
                      HVMCOPY_from_guest | HVMCOPY_fault | HVMCOPY_phys,
                      0);
}

enum hvm_copy_result hvm_copy_to_guest_virt(
    unsigned long vaddr, void *buf, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_to_guest | HVMCOPY_fault | HVMCOPY_virt,
                      PFEC_page_present | PFEC_write_access | pfec);
}

enum hvm_copy_result hvm_copy_from_guest_virt(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

enum hvm_copy_result hvm_fetch_from_guest_virt(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    if ( hvm_nx_enabled(current) )
        pfec |= PFEC_insn_fetch;
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

enum hvm_copy_result hvm_copy_to_guest_virt_nofault(
    unsigned long vaddr, void *buf, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_to_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | PFEC_write_access | pfec);
}

enum hvm_copy_result hvm_copy_from_guest_virt_nofault(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

enum hvm_copy_result hvm_fetch_from_guest_virt_nofault(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    if ( hvm_nx_enabled(current) )
        pfec |= PFEC_insn_fetch;
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

#ifdef __x86_64__
DEFINE_PER_CPU(bool_t, hvm_64bit_hcall);
#endif

unsigned long copy_to_user_hvm(void *to, const void *from, unsigned int len)
{
    int rc;

#ifdef __x86_64__
    if ( !this_cpu(hvm_64bit_hcall) && is_compat_arg_xlat_range(to, len) )
    {
        memcpy(to, from, len);
        return 0;
    }
#endif

    rc = hvm_copy_to_guest_virt_nofault((unsigned long)to, (void *)from,
                                        len, 0);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len)
{
    int rc;

#ifdef __x86_64__
    if ( !this_cpu(hvm_64bit_hcall) && is_compat_arg_xlat_range(from, len) )
    {
        memcpy(to, from, len);
        return 0;
    }
#endif

    rc = hvm_copy_from_guest_virt_nofault(to, (unsigned long)from, len, 0);
    return rc ? len : 0; /* fake a copy_from_user() return code */
}

#define bitmaskof(idx)  (1U << ((idx) & 31))
void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx)
{
    struct vcpu *v = current;
    unsigned int count = *ecx;

    if ( cpuid_viridian_leaves(input, eax, ebx, ecx, edx) )
        return;

    if ( cpuid_hypervisor_leaves(input, count, eax, ebx, ecx, edx) )
        return;

    domain_cpuid(v->domain, input, *ecx, eax, ebx, ecx, edx);

    switch ( input )
    {
    case 0x1:
        /* Fix up VLAPIC details. */
        *ebx &= 0x00FFFFFFu;
        *ebx |= (v->vcpu_id * 2) << 24;
        if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
            __clear_bit(X86_FEATURE_APIC & 31, edx);

        /* Fix up XSAVE and OSXSAVE. */
        *ecx &= ~(bitmaskof(X86_FEATURE_XSAVE) |
                  bitmaskof(X86_FEATURE_OSXSAVE));
        if ( cpu_has_xsave )
        {
            *ecx |= bitmaskof(X86_FEATURE_XSAVE);
            *ecx |= (v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_OSXSAVE) ?
                     bitmaskof(X86_FEATURE_OSXSAVE) : 0;
        }
        break;
    case 0xb:
        /* Fix the x2APIC identifier. */
        *edx = v->vcpu_id * 2;
        break;
    case 0xd:
        if ( cpu_has_xsave )
        {
            /*
             *  Fix up "Processor Extended State Enumeration". We only present
             *  FPU(bit0) and SSE(bit1) to HVM guest for now.
             */
            *eax = *ebx = *ecx = *edx = 0;
            switch ( count )
            {
            case 0:
                /* No HW defines bit in EDX yet. */
                *edx = 0;
                /* We only enable the features we know. */
                *eax = xfeature_low;
                /* FP/SSE + XSAVE.HEADER + YMM. */
                *ecx = 512 + 64 + ((*eax & XSTATE_YMM) ? XSTATE_YMM_SIZE : 0);
                /* Let ebx equal ecx at present. */
                *ebx = *ecx;
                break;
            case 2:
                if ( !(xfeature_low & XSTATE_YMM) )
                    break;
                *eax = XSTATE_YMM_SIZE;
                *ebx = XSTATE_YMM_OFFSET;
                break;
            case 1:
            default:
                break;
            }
        }
        break;
    case 0x80000001:
        /* We expose RDTSCP feature to guest only when
           tsc_mode == TSC_MODE_DEFAULT and host_tsc_is_safe() returns 1 */
        if ( v->domain->arch.tsc_mode != TSC_MODE_DEFAULT ||
             !host_tsc_is_safe() )
            *edx &= ~bitmaskof(X86_FEATURE_RDTSCP);
        break;
    }
}

void hvm_rdtsc_intercept(struct cpu_user_regs *regs)
{
    uint64_t tsc;
    struct vcpu *v = current;

    tsc = hvm_get_guest_tsc(v);
    regs->eax = (uint32_t)tsc;
    regs->edx = (uint32_t)(tsc >> 32);
}

int hvm_msr_read_intercept(struct cpu_user_regs *regs)
{
    uint32_t ecx = regs->ecx;
    uint64_t msr_content = 0;
    struct vcpu *v = current;
    uint64_t *var_range_base, *fixed_range_base;
    int index, mtrr;
    uint32_t cpuid[4];
    int ret;

    var_range_base = (uint64_t *)v->arch.hvm_vcpu.mtrr.var_ranges;
    fixed_range_base = (uint64_t *)v->arch.hvm_vcpu.mtrr.fixed_ranges;

    hvm_cpuid(1, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
    mtrr = !!(cpuid[3] & bitmaskof(X86_FEATURE_MTRR));

    switch ( ecx )
    {
    case MSR_IA32_TSC:
        msr_content = hvm_get_guest_tsc(v);
        break;

    case MSR_TSC_AUX:
        msr_content = hvm_msr_tsc_aux(v);
        break;

    case MSR_IA32_APICBASE:
        msr_content = vcpu_vlapic(v)->hw.apic_base_msr;
        break;

    case MSR_IA32_CR_PAT:
        msr_content = v->arch.hvm_vcpu.pat_cr;
        break;

    case MSR_MTRRcap:
        if ( !mtrr )
            goto gp_fault;
        msr_content = v->arch.hvm_vcpu.mtrr.mtrr_cap;
        break;
    case MSR_MTRRdefType:
        if ( !mtrr )
            goto gp_fault;
        msr_content = v->arch.hvm_vcpu.mtrr.def_type
                        | (v->arch.hvm_vcpu.mtrr.enabled << 10);
        break;
    case MSR_MTRRfix64K_00000:
        if ( !mtrr )
            goto gp_fault;
        msr_content = fixed_range_base[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !mtrr )
            goto gp_fault;
        index = regs->ecx - MSR_MTRRfix16K_80000;
        msr_content = fixed_range_base[index + 1];
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !mtrr )
            goto gp_fault;
        index = regs->ecx - MSR_MTRRfix4K_C0000;
        msr_content = fixed_range_base[index + 3];
        break;
    case MSR_IA32_MTRR_PHYSBASE0...MSR_IA32_MTRR_PHYSMASK7:
        if ( !mtrr )
            goto gp_fault;
        index = regs->ecx - MSR_IA32_MTRR_PHYSBASE0;
        msr_content = var_range_base[index];
        break;

    case MSR_K8_ENABLE_C1E:
    case MSR_AMD64_NB_CFG:
         /*
          * These AMD-only registers may be accessed if this HVM guest
          * has been migrated to an Intel host. This fixes a guest crash
          * in this case.
          */
         msr_content = 0;
         break;

    default:
        ret = mce_rdmsr(ecx, &msr_content);
        if ( ret < 0 )
            goto gp_fault;
        else if ( ret )
            break;
        /* ret == 0, This is not an MCE MSR, see other MSRs */
        else if (!ret)
            return hvm_funcs.msr_read_intercept(regs);
    }

    regs->eax = (uint32_t)msr_content;
    regs->edx = (uint32_t)(msr_content >> 32);
    return X86EMUL_OKAY;

gp_fault:
    hvm_inject_exception(TRAP_gp_fault, 0, 0);
    return X86EMUL_EXCEPTION;
}

int hvm_msr_write_intercept(struct cpu_user_regs *regs)
{
    uint32_t ecx = regs->ecx;
    uint64_t msr_content = (uint32_t)regs->eax | ((uint64_t)regs->edx << 32);
    struct vcpu *v = current;
    int index, mtrr;
    uint32_t cpuid[4];
    int ret;

    hvm_cpuid(1, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
    mtrr = !!(cpuid[3] & bitmaskof(X86_FEATURE_MTRR));

    switch ( ecx )
    {
    case MSR_IA32_TSC:
        hvm_set_guest_tsc(v, msr_content);
        break;

    case MSR_TSC_AUX:
        v->arch.hvm_vcpu.msr_tsc_aux = (uint32_t)msr_content;
        if ( cpu_has_rdtscp
             && (v->domain->arch.tsc_mode != TSC_MODE_PVRDTSCP) )
            wrmsrl(MSR_TSC_AUX, (uint32_t)msr_content);
        break;

    case MSR_IA32_APICBASE:
        vlapic_msr_set(vcpu_vlapic(v), msr_content);
        break;

    case MSR_IA32_CR_PAT:
        if ( !pat_msr_set(&v->arch.hvm_vcpu.pat_cr, msr_content) )
           goto gp_fault;
        break;

    case MSR_MTRRcap:
        if ( !mtrr )
            goto gp_fault;
        goto gp_fault;
    case MSR_MTRRdefType:
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_def_type_msr_set(&v->arch.hvm_vcpu.mtrr, msr_content) )
           goto gp_fault;
        break;
    case MSR_MTRRfix64K_00000:
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr, 0, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !mtrr )
            goto gp_fault;
        index = regs->ecx - MSR_MTRRfix16K_80000 + 1;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !mtrr )
            goto gp_fault;
        index = regs->ecx - MSR_MTRRfix4K_C0000 + 3;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_IA32_MTRR_PHYSBASE0...MSR_IA32_MTRR_PHYSMASK7:
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_var_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     regs->ecx, msr_content) )
            goto gp_fault;
        break;

    case MSR_AMD64_NB_CFG:
        /* ignore the write */
        break;

    default:
        ret = mce_wrmsr(ecx, msr_content);
        if ( ret < 0 )
            goto gp_fault;
        else if ( ret )
            break;
        else if (!ret)
            return hvm_funcs.msr_write_intercept(regs);
    }

    return X86EMUL_OKAY;

gp_fault:
    hvm_inject_exception(TRAP_gp_fault, 0, 0);
    return X86EMUL_EXCEPTION;
}

enum hvm_intblk hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack)
{
    unsigned long intr_shadow;

    ASSERT(v == current);

    if ( (intack.source != hvm_intsrc_nmi) &&
         !(guest_cpu_user_regs()->eflags & X86_EFLAGS_IF) )
        return hvm_intblk_rflags_ie;

    intr_shadow = hvm_funcs.get_interrupt_shadow(v);

    if ( intr_shadow & (HVM_INTR_SHADOW_STI|HVM_INTR_SHADOW_MOV_SS) )
        return hvm_intblk_shadow;

    if ( intack.source == hvm_intsrc_nmi )
        return ((intr_shadow & HVM_INTR_SHADOW_NMI) ?
                hvm_intblk_nmi_iret : hvm_intblk_none);

    if ( intack.source == hvm_intsrc_lapic )
    {
        uint32_t tpr = vlapic_get_reg(vcpu_vlapic(v), APIC_TASKPRI) & 0xF0;
        if ( (tpr >> 4) >= (intack.vector >> 4) )
            return hvm_intblk_tpr;
    }

    return hvm_intblk_none;
}

static int grant_table_op_is_allowed(unsigned int cmd)
{
    switch (cmd) {
    case GNTTABOP_query_size:
    case GNTTABOP_setup_table:
    case GNTTABOP_set_version:
    case GNTTABOP_copy:
    case GNTTABOP_map_grant_ref:
    case GNTTABOP_unmap_grant_ref:
        return 1;
    default:
        /* all other commands need auditing */
        return 0;
    }
}

static long hvm_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE(void) uop, unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS; /* all other commands need auditing */
    return do_grant_table_op(cmd, uop, count);
}

static long hvm_memory_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long rc = do_memory_op(cmd, arg);
    if ( (cmd & MEMOP_CMD_MASK) == XENMEM_decrease_reservation )
        current->domain->arch.hvm_domain.qemu_mapcache_invalidate = 1;
    return rc;
}

static long hvm_vcpu_op(
    int cmd, int vcpuid, XEN_GUEST_HANDLE(void) arg)
{
    long rc;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    case VCPUOP_get_runstate_info:
        rc = do_vcpu_op(cmd, vcpuid, arg);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

typedef unsigned long hvm_hypercall_t(
    unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

#define HYPERCALL(x)                                        \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x

#if defined(__i386__)

static hvm_hypercall_t *hvm_hypercall32_table[NR_hypercalls] = {
    [ __HYPERVISOR_memory_op ] = (hvm_hypercall_t *)hvm_memory_op,
    [ __HYPERVISOR_grant_table_op ] = (hvm_hypercall_t *)hvm_grant_table_op,
    [ __HYPERVISOR_vcpu_op ] = (hvm_hypercall_t *)hvm_vcpu_op,
    HYPERCALL(xen_version),
    HYPERCALL(event_channel_op),
    HYPERCALL(sched_op),
    HYPERCALL(hvm_op)
};

#else /* defined(__x86_64__) */

static long hvm_grant_table_op_compat32(unsigned int cmd,
                                        XEN_GUEST_HANDLE(void) uop,
                                        unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS;
    return compat_grant_table_op(cmd, uop, count);
}

static long hvm_memory_op_compat32(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long rc = compat_memory_op(cmd, arg);
    if ( (cmd & MEMOP_CMD_MASK) == XENMEM_decrease_reservation )
        current->domain->arch.hvm_domain.qemu_mapcache_invalidate = 1;
    return rc;
}

static long hvm_vcpu_op_compat32(
    int cmd, int vcpuid, XEN_GUEST_HANDLE(void) arg)
{
    long rc;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    case VCPUOP_get_runstate_info:
        rc = compat_vcpu_op(cmd, vcpuid, arg);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

static hvm_hypercall_t *hvm_hypercall64_table[NR_hypercalls] = {
    [ __HYPERVISOR_memory_op ] = (hvm_hypercall_t *)hvm_memory_op,
    [ __HYPERVISOR_grant_table_op ] = (hvm_hypercall_t *)hvm_grant_table_op,
    [ __HYPERVISOR_vcpu_op ] = (hvm_hypercall_t *)hvm_vcpu_op,
    HYPERCALL(xen_version),
    HYPERCALL(event_channel_op),
    HYPERCALL(sched_op),
    HYPERCALL(hvm_op)
};

static hvm_hypercall_t *hvm_hypercall32_table[NR_hypercalls] = {
    [ __HYPERVISOR_memory_op ] = (hvm_hypercall_t *)hvm_memory_op_compat32,
    [ __HYPERVISOR_grant_table_op ] = (hvm_hypercall_t *)hvm_grant_table_op_compat32,
    [ __HYPERVISOR_vcpu_op ] = (hvm_hypercall_t *)hvm_vcpu_op_compat32,
    HYPERCALL(xen_version),
    HYPERCALL(event_channel_op),
    HYPERCALL(sched_op),
    HYPERCALL(hvm_op)
};

#endif /* defined(__x86_64__) */

int hvm_do_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct segment_register sreg;
    int mode = hvm_guest_x86_mode(curr);
    uint32_t eax = regs->eax;

    switch ( mode )
    {
#ifdef __x86_64__
    case 8:        
#endif
    case 4:
    case 2:
        hvm_get_segment_register(curr, x86_seg_ss, &sreg);
        if ( unlikely(sreg.attr.fields.dpl == 3) )
        {
    default:
            regs->eax = -EPERM;
            return HVM_HCALL_completed;
        }
    case 0:
        break;
    }

    if ( (eax & 0x80000000) && is_viridian_domain(curr->domain) )
        return viridian_hypercall(regs);

    if ( (eax >= NR_hypercalls) || !hvm_hypercall32_table[eax] )
    {
        regs->eax = -ENOSYS;
        return HVM_HCALL_completed;
    }

    this_cpu(hc_preempted) = 0;

#ifdef __x86_64__
    if ( mode == 8 )
    {
        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%u(%lx, %lx, %lx, %lx, %lx)", eax,
                    regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8);

        this_cpu(hvm_64bit_hcall) = 1;
        regs->rax = hvm_hypercall64_table[eax](regs->rdi,
                                               regs->rsi,
                                               regs->rdx,
                                               regs->r10,
                                               regs->r8); 
        this_cpu(hvm_64bit_hcall) = 0;
    }
    else
#endif
    {
        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%u(%x, %x, %x, %x, %x)", eax,
                    (uint32_t)regs->ebx, (uint32_t)regs->ecx,
                    (uint32_t)regs->edx, (uint32_t)regs->esi,
                    (uint32_t)regs->edi);

        regs->eax = hvm_hypercall32_table[eax]((uint32_t)regs->ebx,
                                               (uint32_t)regs->ecx,
                                               (uint32_t)regs->edx,
                                               (uint32_t)regs->esi,
                                               (uint32_t)regs->edi);
    }

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%u -> %lx",
                eax, (unsigned long)regs->eax);

    if ( this_cpu(hc_preempted) )
        return HVM_HCALL_preempted;

    if ( unlikely(curr->domain->arch.hvm_domain.qemu_mapcache_invalidate) &&
         test_and_clear_bool(curr->domain->arch.hvm_domain.
                             qemu_mapcache_invalidate) )
        return HVM_HCALL_invalidate;

    return HVM_HCALL_completed;
}

static void hvm_latch_shinfo_size(struct domain *d)
{
    bool_t new_has_32bit;

    /*
     * Called from operations which are among the very first executed by
     * PV drivers on initialisation or after save/restore. These are sensible
     * points at which to sample the execution mode of the guest and latch
     * 32- or 64-bit format for shared state.
     */
    if ( current->domain == d ) {
        new_has_32bit = (hvm_guest_x86_mode(current) != 8);
        if (new_has_32bit != d->arch.has_32bit_shinfo) {
            d->arch.has_32bit_shinfo = new_has_32bit;
            /*
             * Make sure that the timebase in the shared info
             * structure is correct for its new bit-ness.  We should
             * arguably try to convert the other fields as well, but
             * that's much more problematic (e.g. what do you do if
             * you're going from 64 bit to 32 bit and there's an event
             * channel pending which doesn't exist in the 32 bit
             * version?).  Just setting the wallclock time seems to be
             * sufficient for everything we do, even if it is a bit of
             * a hack.
             */
            update_domain_wallclock_time(d);
        }
    }
}

/* Initialise a hypercall transfer page for a VMX domain using
   paravirtualised drivers. */
void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page)
{
    hvm_latch_shinfo_size(d);
    hvm_funcs.init_hypercall_page(d, hypercall_page);
}

static int hvmop_set_pci_intx_level(
    XEN_GUEST_HANDLE(xen_hvm_set_pci_intx_level_t) uop)
{
    struct xen_hvm_set_pci_intx_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.domain > 0) || (op.bus > 0) || (op.device > 31) || (op.intx > 3) )
        return -EINVAL;

    d = rcu_lock_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EPERM;
    if ( !IS_PRIV_FOR(current->domain, d) )
        goto out;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_pci_intx_level(d);
    if ( rc )
        goto out;

    rc = 0;
    switch ( op.level )
    {
    case 0:
        hvm_pci_intx_deassert(d, op.device, op.intx);
        break;
    case 1:
        hvm_pci_intx_assert(d, op.device, op.intx);
        break;
    default:
        rc = -EINVAL;
        break;
    }

 out:
    rcu_unlock_domain(d);
    return rc;
}

void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip)
{
    struct domain *d = v->domain;
    struct vcpu_guest_context *ctxt;
    struct segment_register reg;

    BUG_ON(vcpu_runnable(v));

    domain_lock(d);

    if ( v->is_initialised )
        goto out;

    if ( !paging_mode_hap(d) )
    {
        if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_null();
    }

    ctxt = &v->arch.guest_context;
    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->flags = VGCF_online;
    ctxt->user_regs.eflags = 2;
    ctxt->user_regs.edx = 0x00000f00;
    ctxt->user_regs.eip = ip;

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_ET;
    hvm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[2] = 0;
    hvm_update_guest_cr(v, 2);

    v->arch.hvm_vcpu.guest_cr[3] = 0;
    hvm_update_guest_cr(v, 3);

    v->arch.hvm_vcpu.guest_cr[4] = 0;
    hvm_update_guest_cr(v, 4);

    v->arch.hvm_vcpu.guest_efer = 0;
    hvm_update_guest_efer(v);

    reg.sel = cs;
    reg.base = (uint32_t)reg.sel << 4;
    reg.limit = 0xffff;
    reg.attr.bytes = 0x09b;
    hvm_set_segment_register(v, x86_seg_cs, &reg);

    reg.sel = reg.base = 0;
    reg.limit = 0xffff;
    reg.attr.bytes = 0x093;
    hvm_set_segment_register(v, x86_seg_ds, &reg);
    hvm_set_segment_register(v, x86_seg_es, &reg);
    hvm_set_segment_register(v, x86_seg_fs, &reg);
    hvm_set_segment_register(v, x86_seg_gs, &reg);
    hvm_set_segment_register(v, x86_seg_ss, &reg);

    reg.attr.bytes = 0x82; /* LDT */
    hvm_set_segment_register(v, x86_seg_ldtr, &reg);

    reg.attr.bytes = 0x8b; /* 32-bit TSS (busy) */
    hvm_set_segment_register(v, x86_seg_tr, &reg);

    reg.attr.bytes = 0;
    hvm_set_segment_register(v, x86_seg_gdtr, &reg);
    hvm_set_segment_register(v, x86_seg_idtr, &reg);

    /* Sync AP's TSC with BSP's. */
    v->arch.hvm_vcpu.cache_tsc_offset =
        v->domain->vcpu[0]->arch.hvm_vcpu.cache_tsc_offset;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);

    paging_update_paging_modes(v);

    v->arch.flags |= TF_kernel_mode;
    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

 out:
    domain_unlock(d);
}

static void hvm_s3_suspend(struct domain *d)
{
    struct vcpu *v;

    domain_pause(d);
    domain_lock(d);

    if ( d->is_dying || (d->vcpu == NULL) || (d->vcpu[0] == NULL) ||
         test_and_set_bool(d->arch.hvm_domain.is_s3_suspended) )
    {
        domain_unlock(d);
        domain_unpause(d);
        return;
    }

    for_each_vcpu ( d, v )
    {
        vlapic_reset(vcpu_vlapic(v));
        vcpu_reset(v);
    }

    vpic_reset(d);
    vioapic_reset(d);
    pit_reset(d);
    rtc_reset(d);
    pmtimer_reset(d);
    hpet_reset(d);

    hvm_vcpu_reset_state(d->vcpu[0], 0xf000, 0xfff0);

    domain_unlock(d);
}

static void hvm_s3_resume(struct domain *d)
{
    if ( test_and_clear_bool(d->arch.hvm_domain.is_s3_suspended) )
        domain_unpause(d);
}

static int hvmop_set_isa_irq_level(
    XEN_GUEST_HANDLE(xen_hvm_set_isa_irq_level_t) uop)
{
    struct xen_hvm_set_isa_irq_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( op.isa_irq > 15 )
        return -EINVAL;

    d = rcu_lock_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EPERM;
    if ( !IS_PRIV_FOR(current->domain, d) )
        goto out;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_isa_irq_level(d);
    if ( rc )
        goto out;

    rc = 0;
    switch ( op.level )
    {
    case 0:
        hvm_isa_irq_deassert(d, op.isa_irq);
        break;
    case 1:
        hvm_isa_irq_assert(d, op.isa_irq);
        break;
    default:
        rc = -EINVAL;
        break;
    }

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_set_pci_link_route(
    XEN_GUEST_HANDLE(xen_hvm_set_pci_link_route_t) uop)
{
    struct xen_hvm_set_pci_link_route op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.link > 3) || (op.isa_irq > 15) )
        return -EINVAL;

    d = rcu_lock_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EPERM;
    if ( !IS_PRIV_FOR(current->domain, d) )
        goto out;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_pci_link_route(d);
    if ( rc )
        goto out;

    rc = 0;
    hvm_set_pci_link_route(d, op.link, op.isa_irq);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_flush_tlb_all(void)
{
    struct domain *d = current->domain;
    struct vcpu *v;

    if ( !is_hvm_domain(d) )
        return -EINVAL;

    /* Avoid deadlock if more than one vcpu tries this at the same time. */
    if ( !spin_trylock(&d->hypercall_deadlock_mutex) )
        return -EAGAIN;

    /* Pause all other vcpus. */
    for_each_vcpu ( d, v )
        if ( v != current )
            vcpu_pause_nosync(v);

    /* Now that all VCPUs are signalled to deschedule, we wait... */
    for_each_vcpu ( d, v )
        if ( v != current )
            while ( !vcpu_runnable(v) && v->is_running )
                cpu_relax();

    /* All other vcpus are paused, safe to unlock now. */
    spin_unlock(&d->hypercall_deadlock_mutex);

    /* Flush paging-mode soft state (e.g., va->gfn cache; PAE PDPE cache). */
    for_each_vcpu ( d, v )
        paging_update_cr3(v);

    /* Flush all dirty TLBs. */
    flush_tlb_mask(&d->domain_dirty_cpumask);

    /* Done. */
    for_each_vcpu ( d, v )
        if ( v != current )
            vcpu_unpause(v);

    return 0;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE(void) arg)

{
    struct domain *curr_d = current->domain;
    long rc = 0;

    switch ( op )
    {
    case HVMOP_set_param:
    case HVMOP_get_param:
    {
        struct xen_hvm_param a;
        struct hvm_ioreq_page *iorp;
        struct domain *d;
        struct vcpu *v;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        if ( a.index >= HVM_NR_PARAMS )
            return -EINVAL;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail;

        rc = xsm_hvm_param(d, op);
        if ( rc )
            goto param_fail;

        if ( op == HVMOP_set_param )
        {
            rc = 0;

            switch ( a.index )
            {
            case HVM_PARAM_IOREQ_PFN:
                iorp = &d->arch.hvm_domain.ioreq;
                if ( (rc = hvm_set_ioreq_page(d, iorp, a.value)) != 0 )
                    break;
                spin_lock(&iorp->lock);
                if ( iorp->va != NULL )
                    /* Initialise evtchn port info if VCPUs already created. */
                    for_each_vcpu ( d, v )
                        get_ioreq(v)->vp_eport = v->arch.hvm_vcpu.xen_port;
                spin_unlock(&iorp->lock);
                break;
            case HVM_PARAM_BUFIOREQ_PFN: 
                iorp = &d->arch.hvm_domain.buf_ioreq;
                rc = hvm_set_ioreq_page(d, iorp, a.value);
                break;
            case HVM_PARAM_CALLBACK_IRQ:
                hvm_set_callback_via(d, a.value);
                hvm_latch_shinfo_size(d);
                break;
            case HVM_PARAM_TIMER_MODE:
                if ( a.value > HVMPTM_one_missed_tick_pending )
                    rc = -EINVAL;
                break;
            case HVM_PARAM_VIRIDIAN:
                if ( a.value > 1 )
                    rc = -EINVAL;
                break;
            case HVM_PARAM_IDENT_PT:
                /* Not reflexive, as we must domain_pause(). */
                rc = -EPERM;
                if ( curr_d == d )
                    break;

                rc = -EINVAL;
                if ( d->arch.hvm_domain.params[a.index] != 0 )
                    break;

                rc = 0;
                if ( !paging_mode_hap(d) )
                    break;

                /*
                 * Update GUEST_CR3 in each VMCS to point at identity map.
                 * All foreign updates to guest state must synchronise on
                 * the domctl_lock.
                 */
                rc = -EAGAIN;
                if ( !domctl_lock_acquire() )
                    break;

                rc = 0;
                domain_pause(d);
                d->arch.hvm_domain.params[a.index] = a.value;
                for_each_vcpu ( d, v )
                    paging_update_cr3(v);
                domain_unpause(d);

                domctl_lock_release();
                break;
            case HVM_PARAM_DM_DOMAIN:
                /* Not reflexive, as we must domain_pause(). */
                rc = -EPERM;
                if ( curr_d == d )
                    break;

                if ( a.value == DOMID_SELF )
                    a.value = curr_d->domain_id;

                rc = 0;
                domain_pause(d); /* safe to change per-vcpu xen_port */
                iorp = &d->arch.hvm_domain.ioreq;
                for_each_vcpu ( d, v )
                {
                    int old_port, new_port;
                    new_port = alloc_unbound_xen_event_channel(v, a.value);
                    if ( new_port < 0 )
                    {
                        rc = new_port;
                        break;
                    }
                    /* xchg() ensures that only we free_xen_event_channel() */
                    old_port = xchg(&v->arch.hvm_vcpu.xen_port, new_port);
                    free_xen_event_channel(v, old_port);
                    spin_lock(&iorp->lock);
                    if ( iorp->va != NULL )
                        get_ioreq(v)->vp_eport = v->arch.hvm_vcpu.xen_port;
                    spin_unlock(&iorp->lock);
                }
                domain_unpause(d);
                break;
            case HVM_PARAM_ACPI_S_STATE:
                /* Not reflexive, as we must domain_pause(). */
                rc = -EPERM;
                if ( curr_d == d )
                    break;

                rc = 0;
                if ( a.value == 3 )
                    hvm_s3_suspend(d);
                else if ( a.value == 0 )
                    hvm_s3_resume(d);
                else
                    rc = -EINVAL;

                break;
            }

            if ( rc == 0 )
                d->arch.hvm_domain.params[a.index] = a.value;
        }
        else
        {
            switch ( a.index )
            {
            case HVM_PARAM_ACPI_S_STATE:
                a.value = d->arch.hvm_domain.is_s3_suspended ? 3 : 0;
                break;
            default:
                a.value = d->arch.hvm_domain.params[a.index];
                break;
            }
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

        HVM_DBG_LOG(DBG_LEVEL_HCALL, "%s param %u = %"PRIx64,
                    op == HVMOP_set_param ? "set" : "get",
                    a.index, a.value);

    param_fail:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_set_pci_intx_level:
        rc = hvmop_set_pci_intx_level(
            guest_handle_cast(arg, xen_hvm_set_pci_intx_level_t));
        break;

    case HVMOP_set_isa_irq_level:
        rc = hvmop_set_isa_irq_level(
            guest_handle_cast(arg, xen_hvm_set_isa_irq_level_t));
        break;

    case HVMOP_set_pci_link_route:
        rc = hvmop_set_pci_link_route(
            guest_handle_cast(arg, xen_hvm_set_pci_link_route_t));
        break;

    case HVMOP_flush_tlbs:
        rc = guest_handle_is_null(arg) ? hvmop_flush_tlb_all() : -ENOSYS;
        break;

    case HVMOP_track_dirty_vram:
    {
        struct xen_hvm_track_dirty_vram a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail2;

        rc = xsm_hvm_param(d, op);
        if ( rc )
            goto param_fail2;

        rc = -ESRCH;
        if ( d->is_dying )
            goto param_fail2;

        rc = -EINVAL;
        if ( d->vcpu == NULL || d->vcpu[0] == NULL )
            goto param_fail2;

        if ( shadow_mode_enabled(d) )
            rc = shadow_track_dirty_vram(d, a.first_pfn, a.nr, a.dirty_bitmap);
        else
            rc = hap_track_dirty_vram(d, a.first_pfn, a.nr, a.dirty_bitmap);

    param_fail2:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_modified_memory:
    {
        struct xen_hvm_modified_memory a;
        struct domain *d;
        unsigned long pfn;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail3;

        rc = xsm_hvm_param(d, op);
        if ( rc )
            goto param_fail3;

        rc = -EINVAL;
        if ( (a.first_pfn > domain_get_maximum_gpfn(d)) ||
             ((a.first_pfn + a.nr - 1) < a.first_pfn) ||
             ((a.first_pfn + a.nr - 1) > domain_get_maximum_gpfn(d)) )
            goto param_fail3;

        rc = 0;
        if ( !paging_mode_log_dirty(d) )
            goto param_fail3;

        for ( pfn = a.first_pfn; pfn < a.first_pfn + a.nr; pfn++ )
        {
            p2m_type_t t;
            mfn_t mfn = gfn_to_mfn(d, pfn, &t);
            if ( p2m_is_paging(t) )
            {
                p2m_mem_paging_populate(d, pfn);

                rc = -EINVAL;
                goto param_fail3;
            }
            if( p2m_is_shared(t) )
                gdprintk(XENLOG_WARNING,
                         "shared pfn 0x%lx modified?\n", pfn);
            
            if ( mfn_x(mfn) != INVALID_MFN )
            {
                paging_mark_dirty(d, mfn_x(mfn));
                /* These are most probably not page tables any more */
                /* don't take a long time and don't die either */
                sh_remove_shadows(d->vcpu[0], mfn, 1, 0);
            }
        }

    param_fail3:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_set_mem_type:
    {
        struct xen_hvm_set_mem_type a;
        struct domain *d;
        unsigned long pfn;
        
        /* Interface types to internal p2m types */
        p2m_type_t memtype[] = {
            p2m_ram_rw,        /* HVMMEM_ram_rw  */
            p2m_ram_ro,        /* HVMMEM_ram_ro  */
            p2m_mmio_dm        /* HVMMEM_mmio_dm */
        };

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail4;

        rc = -EINVAL;
        if ( (a.first_pfn > domain_get_maximum_gpfn(d)) ||
             ((a.first_pfn + a.nr - 1) < a.first_pfn) ||
             ((a.first_pfn + a.nr - 1) > domain_get_maximum_gpfn(d)) )
            goto param_fail4;
            
        if ( a.hvmmem_type >= ARRAY_SIZE(memtype) )
            goto param_fail4;

        for ( pfn = a.first_pfn; pfn < a.first_pfn + a.nr; pfn++ )
        {
            p2m_type_t t;
            p2m_type_t nt;
            mfn_t mfn;
            mfn = gfn_to_mfn_unshare(d, pfn, &t, 0);
            if ( p2m_is_paging(t) )
            {
                p2m_mem_paging_populate(d, pfn);

                rc = -EINVAL;
                goto param_fail4;
            }
            if ( p2m_is_shared(t) )
            {
                rc = -EINVAL;
                goto param_fail4;
            } 
            if ( p2m_is_grant(t) )
            {
                gdprintk(XENLOG_WARNING,
                         "type for pfn 0x%lx changed to grant while "
                         "we were working?\n", pfn);
                goto param_fail4;
            }
            else
            {
                nt = p2m_change_type(d, pfn, t, memtype[a.hvmmem_type]);
                if ( nt != t )
                {
                    gdprintk(XENLOG_WARNING,
                             "type of pfn 0x%lx changed from %d to %d while "
                             "we were trying to change it to %d\n",
                             pfn, t, nt, memtype[a.hvmmem_type]);
                    goto param_fail4;
                }
            }
        }

        rc = 0;

    param_fail4:
        rcu_unlock_domain(d);
        break;
    }

    default:
    {
        gdprintk(XENLOG_WARNING, "Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
        break;
    }
    }

    if ( rc == -EAGAIN )
        rc = hypercall_create_continuation(
            __HYPERVISOR_hvm_op, "lh", op, arg);

    return rc;
}

int hvm_debug_op(struct vcpu *v, int32_t op)
{
    int rc;

    switch ( op )
    {
        case XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON:
        case XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF:
            rc = -ENOSYS;
            if ( !cpu_has_monitor_trap_flag )
                break;
            rc = 0;
            vcpu_pause(v);
            v->arch.hvm_vcpu.single_step =
                (op == XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON);
            vcpu_unpause(v); /* guest will latch new state */
            break;
        default:
            rc = -ENOSYS;
            break;
    }

    return rc;
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

