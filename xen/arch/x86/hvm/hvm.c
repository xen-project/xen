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
#include <xen/cpu.h>
#include <xen/wait.h>
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
#include <asm/xstate.h>
#include <asm/traps.h>
#include <asm/mc146818rtc.h>
#include <asm/spinlock.h>
#include <asm/mce.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/hvm/trace.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/mtrr.h>
#include <asm/apic.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/version.h>
#include <public/memory.h>
#include <asm/mem_event.h>
#include <asm/mem_access.h>
#include <public/mem_event.h>

bool_t __read_mostly hvm_enabled;

unsigned int opt_hvm_debug_level __read_mostly;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs __read_mostly;

/* I/O permission bitmap is globally shared by all HVM guests. */
unsigned long __attribute__ ((__section__ (".bss.page_aligned")))
    hvm_io_bitmap[3*PAGE_SIZE/BYTES_PER_LONG];

/* Xen command-line option to enable HAP */
static bool_t __initdata opt_hap_enabled = 1;
boolean_param("hap", opt_hap_enabled);

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = hvm_funcs.cpu_up_prepare(cpu);
        break;
    case CPU_DYING:
        hvm_cpu_down();
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        hvm_funcs.cpu_dead(cpu);
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

static int __init hvm_enable(void)
{
    const struct hvm_function_table *fns = NULL;

    if ( cpu_has_vmx )
        fns = start_vmx();
    else if ( cpu_has_svm )
        fns = start_svm();

    if ( fns == NULL )
        return 0;

    hvm_funcs = *fns;
    hvm_enabled = 1;

    printk("HVM: %s enabled\n", fns->name);
    if ( !fns->hap_supported )
        printk("HVM: Hardware Assisted Paging (HAP) not detected\n");
    else if ( !opt_hap_enabled )
    {
        hvm_funcs.hap_supported = 0;
        printk("HVM: Hardware Assisted Paging (HAP) detected but disabled\n");
    }
    else
    {
        printk("HVM: Hardware Assisted Paging (HAP) detected\n");
        printk("HVM: HAP page sizes: 4kB");
        if ( fns->hap_capabilities & HVM_HAP_SUPERPAGE_2MB )
            printk(", 2MB%s", opt_hap_2mb ? "" : " [disabled]");
        if ( fns->hap_capabilities & HVM_HAP_SUPERPAGE_1GB )
            printk(", 1GB%s", opt_hap_1gb ? "" : " [disabled]");
        printk("\n");
    }

    if ( !fns->pvh_supported )
        printk(XENLOG_INFO "HVM: PVH mode not supported on this platform\n");

    /*
     * Allow direct access to the PC debug ports 0x80 and 0xed (they are
     * often used for I/O delays, but the vmexits simply slow things down).
     */
    memset(hvm_io_bitmap, ~0, sizeof(hvm_io_bitmap));
    if ( hvm_port80_allowed )
        __clear_bit(0x80, hvm_io_bitmap);
    __clear_bit(0xed, hvm_io_bitmap);

    register_cpu_notifier(&cpu_nfb);

    return 0;
}
presmp_initcall(hvm_enable);

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

void hvm_get_guest_pat(struct vcpu *v, u64 *guest_pat)
{
    if ( !hvm_funcs.get_guest_pat(v, guest_pat) )
        *guest_pat = v->arch.hvm_vcpu.pat_cr;
}

int hvm_set_guest_pat(struct vcpu *v, u64 guest_pat)
{
    int i;
    uint8_t *value = (uint8_t *)&guest_pat;

    for ( i = 0; i < 8; i++ )
        if ( unlikely(!(value[i] == 0 || value[i] == 1 ||
                        value[i] == 4 || value[i] == 5 ||
                        value[i] == 6 || value[i] == 7)) ) {
            HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid guest PAT: %"PRIx64"\n",
                        guest_pat); 
            return 0;
        }

    if ( !hvm_funcs.set_guest_pat(v, guest_pat) )
        v->arch.hvm_vcpu.pat_cr = guest_pat;
    return 1;
}

void hvm_set_guest_tsc(struct vcpu *v, u64 guest_tsc)
{
    uint64_t tsc;
    uint64_t delta_tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time(v);
        tsc = gtime_to_gtsc(v->domain, tsc);
    }
    else
    {
        rdtscll(tsc);
    }

    delta_tsc = guest_tsc - tsc;
    v->arch.hvm_vcpu.msr_tsc_adjust += delta_tsc
                          - v->arch.hvm_vcpu.cache_tsc_offset;
    v->arch.hvm_vcpu.cache_tsc_offset = delta_tsc;

    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);
}

void hvm_set_guest_tsc_adjust(struct vcpu *v, u64 tsc_adjust)
{
    v->arch.hvm_vcpu.cache_tsc_offset += tsc_adjust
                            - v->arch.hvm_vcpu.msr_tsc_adjust;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);
    v->arch.hvm_vcpu.msr_tsc_adjust = tsc_adjust;
}

u64 hvm_get_guest_tsc(struct vcpu *v)
{
    uint64_t tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time(v);
        tsc = gtime_to_gtsc(v->domain, tsc);
        v->domain->arch.vtsc_kerncount++;
    }
    else
    {
        rdtscll(tsc);
    }

    return tsc + v->arch.hvm_vcpu.cache_tsc_offset;
}

u64 hvm_get_guest_tsc_adjust(struct vcpu *v)
{
    return v->arch.hvm_vcpu.msr_tsc_adjust;
}

void hvm_migrate_timers(struct vcpu *v)
{
    /* PVH doesn't use rtc and emulated timers, it uses pvclock mechanism. */
    if ( is_pvh_vcpu(v) )
        return;

    rtc_migrate_timers(v);
    pt_migrate(v);
}

static int hvm_migrate_pirq(struct domain *d, struct hvm_pirq_dpci *pirq_dpci,
                            void *arg)
{
    struct vcpu *v = arg;

    if ( (pirq_dpci->flags & HVM_IRQ_DPCI_MACH_MSI) &&
         (pirq_dpci->gmsi.dest_vcpu_id == v->vcpu_id) )
    {
        struct irq_desc *desc =
            pirq_spin_lock_irq_desc(dpci_pirq(pirq_dpci), NULL);

        if ( !desc )
            return 0;
        ASSERT(MSI_IRQ(desc - irq_desc));
        irq_set_affinity(desc, cpumask_of(v->processor));
        spin_unlock_irq(&desc->lock);
    }

    return 0;
}

void hvm_migrate_pirqs(struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( !iommu_enabled || !d->arch.hvm_domain.irq.dpci )
       return;

    spin_lock(&d->event_lock);
    pt_pirq_iterate(d, hvm_migrate_pirq, v);
    spin_unlock(&d->event_lock);
}

void hvm_do_resume(struct vcpu *v)
{
    ioreq_t *p;

    check_wakeup_from_wait();

    if ( is_hvm_vcpu(v) )
        pt_restore_timer(v);

    /* NB. Optimised for common case (p->state == STATE_IOREQ_NONE). */
    if ( !(p = get_ioreq(v)) )
        goto check_inject_trap;

    while ( p->state != STATE_IOREQ_NONE )
    {
        switch ( p->state )
        {
        case STATE_IORESP_READY: /* IORESP_READY -> NONE */
            hvm_io_assist(p);
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

 check_inject_trap:
    /* Inject pending hw/sw trap */
    if ( v->arch.hvm_vcpu.inject_trap.vector != -1 ) 
    {
        hvm_inject_trap(&v->arch.hvm_vcpu.inject_trap);
        v->arch.hvm_vcpu.inject_trap.vector = -1;
    }
}

static void hvm_init_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    memset(iorp, 0, sizeof(*iorp));
    spin_lock_init(&iorp->lock);
    domain_pause(d);
}

void destroy_ring_for_helper(
    void **_va, struct page_info *page)
{
    void *va = *_va;

    if ( va != NULL )
    {
        unmap_domain_page_global(va);
        put_page_and_type(page);
        *_va = NULL;
    }
}

static void hvm_destroy_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    spin_lock(&iorp->lock);

    ASSERT(d->is_dying);

    destroy_ring_for_helper(&iorp->va, iorp->page);

    spin_unlock(&iorp->lock);
}

int prepare_ring_for_helper(
    struct domain *d, unsigned long gmfn, struct page_info **_page,
    void **_va)
{
    struct page_info *page;
    p2m_type_t p2mt;
    void *va;

    page = get_page_from_gfn(d, gmfn, &p2mt, P2M_UNSHARE);
    if ( p2m_is_paging(p2mt) )
    {
        if ( page )
            put_page(page);
        p2m_mem_paging_populate(d, gmfn);
        return -ENOENT;
    }
    if ( p2m_is_shared(p2mt) )
    {
        if ( page )
            put_page(page);
        return -ENOENT;
    }
    if ( !page )
        return -EINVAL;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return -EINVAL;
    }

    va = __map_domain_page_global(page);
    if ( va == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    *_va = va;
    *_page = page;

    return 0;
}

static int hvm_set_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp, unsigned long gmfn)
{
    struct page_info *page;
    void *va;
    int rc;

    if ( (rc = prepare_ring_for_helper(d, gmfn, &page, &va)) )
        return rc;

    spin_lock(&iorp->lock);

    if ( (iorp->va != NULL) || d->is_dying )
    {
        destroy_ring_for_helper(&va, page);
        spin_unlock(&iorp->lock);
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
    struct domain *cd = current->domain;
    char c = *val;

    BUG_ON(bytes != 1);

    /* Accept only printable characters, newline, and horizontal tab. */
    if ( !isprint(c) && (c != '\n') && (c != '\t') )
        return X86EMUL_OKAY;

    spin_lock(&cd->pbuf_lock);
    if ( c != '\n' )
        cd->pbuf[cd->pbuf_idx++] = c;
    if ( (cd->pbuf_idx == (DOMAIN_PBUF_SIZE - 1)) || (c == '\n') )
    {
        cd->pbuf[cd->pbuf_idx] = '\0';
        guest_printk(cd, XENLOG_G_DEBUG "%s\n", cd->pbuf);
        cd->pbuf_idx = 0;
    }
    spin_unlock(&cd->pbuf_lock);

    return X86EMUL_OKAY;
}

static int handle_pvh_io(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val)
{
    struct vcpu *curr = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    if ( dir == IOREQ_WRITE )
        guest_io_write(port, bytes, *val, curr, regs);
    else
        *val = guest_io_read(port, bytes, curr, regs);

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

    if ( is_pvh_domain(d) )
    {
        if ( !hvm_funcs.pvh_supported )
        {
            printk(XENLOG_G_WARNING "Attempt to create a PVH guest "
                   "on a system without necessary hardware support\n");
            return -EINVAL;
        }
        if ( !hap_enabled(d) )
        {
            printk(XENLOG_G_INFO "PVH guest must have HAP on\n");
            return -EINVAL;
        }

    }

    spin_lock_init(&d->arch.hvm_domain.irq_lock);
    spin_lock_init(&d->arch.hvm_domain.uc_lock);

    INIT_LIST_HEAD(&d->arch.hvm_domain.msixtbl_list);
    spin_lock_init(&d->arch.hvm_domain.msixtbl_list_lock);

    hvm_init_cacheattr_region_list(d);

    rc = paging_enable(d, PG_refcounts|PG_translate|PG_external);
    if ( rc != 0 )
        goto fail0;

    d->arch.hvm_domain.params = xzalloc_array(uint64_t, HVM_NR_PARAMS);
    d->arch.hvm_domain.io_handler = xmalloc(struct hvm_io_handler);
    rc = -ENOMEM;
    if ( !d->arch.hvm_domain.params || !d->arch.hvm_domain.io_handler )
        goto fail1;
    d->arch.hvm_domain.io_handler->num_slot = 0;

    if ( is_pvh_domain(d) )
    {
        register_portio_handler(d, 0, 0x10003, handle_pvh_io);
        return 0;
    }

    hvm_init_guest_time(d);

    d->arch.hvm_domain.params[HVM_PARAM_HPET_ENABLED] = 1;
    d->arch.hvm_domain.params[HVM_PARAM_TRIPLE_FAULT_REASON] = SHUTDOWN_reboot;

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
    xfree(d->arch.hvm_domain.io_handler);
    xfree(d->arch.hvm_domain.params);
 fail0:
    hvm_destroy_cacheattr_region_list(d);
    return rc;
}

void hvm_domain_relinquish_resources(struct domain *d)
{
    xfree(d->arch.hvm_domain.io_handler);
    xfree(d->arch.hvm_domain.params);

    if ( is_pvh_domain(d) )
        return;

    if ( hvm_funcs.nhvm_domain_relinquish_resources )
        hvm_funcs.nhvm_domain_relinquish_resources(d);

    hvm_destroy_ioreq_page(d, &d->arch.hvm_domain.ioreq);
    hvm_destroy_ioreq_page(d, &d->arch.hvm_domain.buf_ioreq);

    msixtbl_pt_cleanup(d);

    /* Stop all asynchronous timer actions. */
    rtc_deinit(d);
    if ( d->vcpu != NULL && d->vcpu[0] != NULL )
    {
        pmtimer_deinit(d);
        hpet_deinit(d);
    }
}

void hvm_domain_destroy(struct domain *d)
{
    hvm_destroy_cacheattr_region_list(d);

    if ( is_pvh_domain(d) )
        return;

    hvm_funcs.domain_destroy(d);
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);
}

static int hvm_save_tsc_adjust(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_tsc_adjust ctxt;
    int err = 0;

    for_each_vcpu ( d, v )
    {
        ctxt.tsc_adjust = v->arch.hvm_vcpu.msr_tsc_adjust;
        err = hvm_save_entry(TSC_ADJUST, v->vcpu_id, h, &ctxt);
        if ( err )
            break;
    }

    return err;
}

static int hvm_load_tsc_adjust(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    struct hvm_tsc_adjust ctxt;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry(TSC_ADJUST, h, &ctxt) != 0 )
        return -EINVAL;

    v->arch.hvm_vcpu.msr_tsc_adjust = ctxt.tsc_adjust;
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(TSC_ADJUST, hvm_save_tsc_adjust,
                          hvm_load_tsc_adjust, 1, HVMSR_PER_VCPU);

static int hvm_save_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;

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

        if ( v->fpu_initialised )
            memcpy(ctxt.fpu_regs, v->arch.fpu_ctxt, sizeof(ctxt.fpu_regs));
        else 
            memset(ctxt.fpu_regs, 0, sizeof(ctxt.fpu_regs));

        ctxt.rax = v->arch.user_regs.eax;
        ctxt.rbx = v->arch.user_regs.ebx;
        ctxt.rcx = v->arch.user_regs.ecx;
        ctxt.rdx = v->arch.user_regs.edx;
        ctxt.rbp = v->arch.user_regs.ebp;
        ctxt.rsi = v->arch.user_regs.esi;
        ctxt.rdi = v->arch.user_regs.edi;
        ctxt.rsp = v->arch.user_regs.esp;
        ctxt.rip = v->arch.user_regs.eip;
        ctxt.rflags = v->arch.user_regs.eflags;
        ctxt.r8  = v->arch.user_regs.r8;
        ctxt.r9  = v->arch.user_regs.r9;
        ctxt.r10 = v->arch.user_regs.r10;
        ctxt.r11 = v->arch.user_regs.r11;
        ctxt.r12 = v->arch.user_regs.r12;
        ctxt.r13 = v->arch.user_regs.r13;
        ctxt.r14 = v->arch.user_regs.r14;
        ctxt.r15 = v->arch.user_regs.r15;
        ctxt.dr0 = v->arch.debugreg[0];
        ctxt.dr1 = v->arch.debugreg[1];
        ctxt.dr2 = v->arch.debugreg[2];
        ctxt.dr3 = v->arch.debugreg[3];
        ctxt.dr6 = v->arch.debugreg[6];
        ctxt.dr7 = v->arch.debugreg[7];

        if ( hvm_save_entry(CPU, v->vcpu_id, h, &ctxt) != 0 )
            return 1; 
    }
    return 0;
}

static bool_t hvm_efer_valid(struct domain *d,
                             uint64_t value, uint64_t efer_validbits)
{
    if ( nestedhvm_enabled(d) && cpu_has_svm )
        efer_validbits |= EFER_SVME;

    return !((value & ~efer_validbits) ||
             ((sizeof(long) != 8) && (value & EFER_LME)) ||
             (!cpu_has_svm && (value & EFER_SVME)) ||
             (!cpu_has_nx && (value & EFER_NX)) ||
             (!cpu_has_syscall && (value & EFER_SCE)) ||
             (!cpu_has_lmsl && (value & EFER_LMSLE)) ||
             (!cpu_has_ffxsr && (value & EFER_FFXSE)) ||
             ((value & (EFER_LME|EFER_LMA)) == EFER_LMA));
}

static int hvm_load_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid;
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;
    uint64_t efer_validbits;

    /* Which vcpu is this? */
    vcpuid = hvm_load_instance(h);
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%u has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry(CPU, h, &ctxt) != 0 ) 
        return -EINVAL;

    /* Sanity check some control registers. */
    if ( (ctxt.cr0 & HVM_CR0_GUEST_RESERVED_BITS) ||
         !(ctxt.cr0 & X86_CR0_ET) ||
         ((ctxt.cr0 & (X86_CR0_PE|X86_CR0_PG)) == X86_CR0_PG) )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad CR0 %#" PRIx64 "\n",
               d->domain_id, ctxt.cr0);
        return -EINVAL;
    }

    if ( ctxt.cr4 & HVM_CR4_GUEST_RESERVED_BITS(v, 1) )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad CR4 %#" PRIx64 "\n",
               d->domain_id, ctxt.cr4);
        return -EINVAL;
    }

    efer_validbits = EFER_FFXSE | EFER_LMSLE | EFER_LME | EFER_LMA
                   | EFER_NX | EFER_SCE;
    if ( !hvm_efer_valid(d, ctxt.msr_efer, efer_validbits) )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad EFER %#" PRIx64 "\n",
               d->domain_id, ctxt.msr_efer);
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

    /* In case xsave-absent save file is restored on a xsave-capable host */
    if ( cpu_has_xsave && !xsave_enabled(v) )
    {
        struct xsave_struct *xsave_area = v->arch.xsave_area;

        memcpy(v->arch.xsave_area, ctxt.fpu_regs, sizeof(ctxt.fpu_regs));
        xsave_area->xsave_hdr.xstate_bv = XSTATE_FP_SSE;
    }
    else
        memcpy(v->arch.fpu_ctxt, ctxt.fpu_regs, sizeof(ctxt.fpu_regs));

    v->arch.user_regs.eax = ctxt.rax;
    v->arch.user_regs.ebx = ctxt.rbx;
    v->arch.user_regs.ecx = ctxt.rcx;
    v->arch.user_regs.edx = ctxt.rdx;
    v->arch.user_regs.ebp = ctxt.rbp;
    v->arch.user_regs.esi = ctxt.rsi;
    v->arch.user_regs.edi = ctxt.rdi;
    v->arch.user_regs.esp = ctxt.rsp;
    v->arch.user_regs.eip = ctxt.rip;
    v->arch.user_regs.eflags = ctxt.rflags | X86_EFLAGS_MBS;
    v->arch.user_regs.r8  = ctxt.r8;
    v->arch.user_regs.r9  = ctxt.r9;
    v->arch.user_regs.r10 = ctxt.r10;
    v->arch.user_regs.r11 = ctxt.r11;
    v->arch.user_regs.r12 = ctxt.r12;
    v->arch.user_regs.r13 = ctxt.r13;
    v->arch.user_regs.r14 = ctxt.r14;
    v->arch.user_regs.r15 = ctxt.r15;
    v->arch.debugreg[0] = ctxt.dr0;
    v->arch.debugreg[1] = ctxt.dr1;
    v->arch.debugreg[2] = ctxt.dr2;
    v->arch.debugreg[3] = ctxt.dr3;
    v->arch.debugreg[6] = ctxt.dr6;
    v->arch.debugreg[7] = ctxt.dr7;

    v->arch.vgc_flags = VGCF_online;
    v->fpu_initialised = 1;

    /* Auxiliary processors should be woken immediately. */
    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);
    vcpu_wake(v);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(CPU, hvm_save_cpu_ctxt, hvm_load_cpu_ctxt,
                          1, HVMSR_PER_VCPU);

#define HVM_CPU_XSAVE_SIZE(xcr0) (offsetof(struct hvm_hw_cpu_xsave, \
                                           save_area) + \
                                  xstate_ctxt_size(xcr0))

static int hvm_save_cpu_xsave_states(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_hw_cpu_xsave *ctxt;

    if ( !cpu_has_xsave )
        return 0;   /* do nothing */

    for_each_vcpu ( d, v )
    {
        unsigned int size = HVM_CPU_XSAVE_SIZE(v->arch.xcr0_accum);

        if ( !xsave_enabled(v) )
            continue;
        if ( _hvm_init_entry(h, CPU_XSAVE_CODE, v->vcpu_id, size) )
            return 1;
        ctxt = (struct hvm_hw_cpu_xsave *)&h->data[h->cur];
        h->cur += size;

        ctxt->xfeature_mask = xfeature_mask;
        ctxt->xcr0 = v->arch.xcr0;
        ctxt->xcr0_accum = v->arch.xcr0_accum;
        memcpy(&ctxt->save_area, v->arch.xsave_area,
               size - offsetof(struct hvm_hw_cpu_xsave, save_area));
    }

    return 0;
}

static int hvm_load_cpu_xsave_states(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid, size;
    int err;
    struct vcpu *v;
    struct hvm_hw_cpu_xsave *ctxt;
    struct hvm_save_descriptor *desc;

    /* Which vcpu is this? */
    vcpuid = hvm_load_instance(h);
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    /* Fails since we can't restore an img saved on xsave-capable host. */
    if ( !cpu_has_xsave )
        return -EOPNOTSUPP;

    /* Customized checking for entry since our entry is of variable length */
    desc = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read xsave descriptor\n",
               d->domain_id, vcpuid);
        return -ENODATA;
    }
    if ( desc->length + sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read %u xsave bytes\n",
               d->domain_id, vcpuid, desc->length);
        return -ENODATA;
    }
    if ( desc->length < offsetof(struct hvm_hw_cpu_xsave, save_area) +
                        XSTATE_AREA_MIN_SIZE )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: xsave length %u < %zu\n",
               d->domain_id, vcpuid, desc->length,
               offsetof(struct hvm_hw_cpu_xsave,
                        save_area) + XSTATE_AREA_MIN_SIZE);
        return -EINVAL;
    }
    size = HVM_CPU_XSAVE_SIZE(xfeature_mask);
    if ( desc->length > size )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: xsave length %u > %u\n",
               d->domain_id, vcpuid, desc->length, size);
        return -EOPNOTSUPP;
    }
    h->cur += sizeof (*desc);

    ctxt = (struct hvm_hw_cpu_xsave *)&h->data[h->cur];
    h->cur += desc->length;

    err = validate_xstate(ctxt->xcr0, ctxt->xcr0_accum,
                          ctxt->save_area.xsave_hdr.xstate_bv,
                          ctxt->xfeature_mask);
    if ( err )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: inconsistent xsave state (feat=%#"PRIx64
               " accum=%#"PRIx64" xcr0=%#"PRIx64" bv=%#"PRIx64" err=%d)\n",
               d->domain_id, vcpuid, ctxt->xfeature_mask, ctxt->xcr0_accum,
               ctxt->xcr0, ctxt->save_area.xsave_hdr.xstate_bv, err);
        return err;
    }
    size = HVM_CPU_XSAVE_SIZE(ctxt->xcr0_accum);
    if ( desc->length > size )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: xsave length %u > %u\n",
               d->domain_id, vcpuid, desc->length, size);
        return -EOPNOTSUPP;
    }
    /* Checking finished */

    v->arch.xcr0 = ctxt->xcr0;
    v->arch.xcr0_accum = ctxt->xcr0_accum;
    if ( ctxt->xcr0_accum & XSTATE_NONLAZY )
        v->arch.nonlazy_xstate_used = 1;
    memcpy(v->arch.xsave_area, &ctxt->save_area,
           desc->length - offsetof(struct hvm_hw_cpu_xsave, save_area));

    return 0;
}

/* We need variable length data chunk for xsave area, hence customized
 * declaration other than HVM_REGISTER_SAVE_RESTORE.
 */
static int __init __hvm_register_CPU_XSAVE_save_and_restore(void)
{
    hvm_register_savevm(CPU_XSAVE_CODE,
                        "CPU_XSAVE",
                        hvm_save_cpu_xsave_states,
                        hvm_load_cpu_xsave_states,
                        HVM_CPU_XSAVE_SIZE(xfeature_mask) +
                            sizeof(struct hvm_save_descriptor),
                        HVMSR_PER_VCPU);
    return 0;
}
__initcall(__hvm_register_CPU_XSAVE_save_and_restore);

int hvm_vcpu_initialise(struct vcpu *v)
{
    int rc;
    struct domain *d = v->domain;
    domid_t dm_domid;

    hvm_asid_flush_vcpu(v);

    spin_lock_init(&v->arch.hvm_vcpu.tm_lock);
    INIT_LIST_HEAD(&v->arch.hvm_vcpu.tm_list);

    rc = hvm_vcpu_cacheattr_init(v); /* teardown: vcpu_cacheattr_destroy */
    if ( rc != 0 )
        goto fail1;

    /* NB: vlapic_init must be called before hvm_funcs.vcpu_initialise */
    if ( is_hvm_vcpu(v) )
        rc = vlapic_init(v);
    if ( rc != 0 ) /* teardown: vlapic_destroy */
        goto fail2;

    if ( (rc = hvm_funcs.vcpu_initialise(v)) != 0 ) /* teardown: hvm_funcs.vcpu_destroy */
        goto fail3;

    softirq_tasklet_init(
        &v->arch.hvm_vcpu.assert_evtchn_irq_tasklet,
        (void(*)(unsigned long))hvm_assert_evtchn_irq,
        (unsigned long)v);

    v->arch.hvm_vcpu.inject_trap.vector = -1;

    if ( is_pvh_vcpu(v) )
    {
        v->arch.hvm_vcpu.hcall_64bit = 1;    /* PVH 32bitfixme. */
        /* This is for hvm_long_mode_enabled(v). */
        v->arch.hvm_vcpu.guest_efer = EFER_SCE | EFER_LMA | EFER_LME;
        return 0;
    }

    rc = setup_compat_arg_xlat(v); /* teardown: free_compat_arg_xlat() */
    if ( rc != 0 )
        goto fail4;

    if ( nestedhvm_enabled(d)
         && (rc = nestedhvm_vcpu_initialise(v)) < 0 ) /* teardown: nestedhvm_vcpu_destroy */
        goto fail5;

    dm_domid = d->arch.hvm_domain.params[HVM_PARAM_DM_DOMAIN];

    /* Create ioreq event channel. */
    rc = alloc_unbound_xen_event_channel(v, dm_domid, NULL); /* teardown: none */
    if ( rc < 0 )
        goto fail6;

    /* Register ioreq event channel. */
    v->arch.hvm_vcpu.xen_port = rc;

    if ( v->vcpu_id == 0 )
    {
        /* Create bufioreq event channel. */
        rc = alloc_unbound_xen_event_channel(v, dm_domid, NULL); /* teardown: none */
        if ( rc < 0 )
            goto fail6;
        d->arch.hvm_domain.params[HVM_PARAM_BUFIOREQ_EVTCHN] = rc;
    }

    spin_lock(&d->arch.hvm_domain.ioreq.lock);
    if ( d->arch.hvm_domain.ioreq.va != NULL )
        get_ioreq(v)->vp_eport = v->arch.hvm_vcpu.xen_port;
    spin_unlock(&d->arch.hvm_domain.ioreq.lock);

    if ( v->vcpu_id == 0 )
    {
        /* NB. All these really belong in hvm_domain_initialise(). */
        pmtimer_init(v);
        hpet_init(v);
 
        /* Init guest TSC to start from zero. */
        hvm_set_guest_tsc(v, 0);

        /* Can start up without SIPI-SIPI or setvcpucontext domctl. */
        v->is_initialised = 1;
        clear_bit(_VPF_down, &v->pause_flags);
    }

    return 0;

 fail6:
    nestedhvm_vcpu_destroy(v);
 fail5:
    free_compat_arg_xlat(v);
 fail4:
    hvm_funcs.vcpu_destroy(v);
 fail3:
    vlapic_destroy(v);
 fail2:
    hvm_vcpu_cacheattr_destroy(v);
 fail1:
    return rc;
}

void hvm_vcpu_destroy(struct vcpu *v)
{
    nestedhvm_vcpu_destroy(v);

    free_compat_arg_xlat(v);

    tasklet_kill(&v->arch.hvm_vcpu.assert_evtchn_irq_tasklet);
    hvm_vcpu_cacheattr_destroy(v);

    if ( is_hvm_vcpu(v) )
        vlapic_destroy(v);

    hvm_funcs.vcpu_destroy(v);

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

    if ( !(p = get_ioreq(v)) )
        return 0;

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
    notify_via_xen_event_channel(v->domain, v->arch.hvm_vcpu.xen_port);

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
    struct domain *d = v->domain;
    u8 reason = d->arch.hvm_domain.params[HVM_PARAM_TRIPLE_FAULT_REASON];

    gdprintk(XENLOG_INFO, "Triple fault on VCPU%d - "
             "invoking HVM shutdown action %"PRIu8".\n",
             v->vcpu_id, reason);
    domain_shutdown(d, reason);
}

void hvm_inject_trap(struct hvm_trap *trap)
{
    struct vcpu *curr = current;

    if ( nestedhvm_enabled(curr->domain) &&
         !nestedhvm_vmswitch_in_progress(curr) &&
         nestedhvm_vcpu_in_guestmode(curr) &&
         nhvm_vmcx_guest_intercepts_trap(
             curr, trap->vector, trap->error_code) )
    {
        enum nestedhvm_vmexits nsret;

        nsret = nhvm_vcpu_vmexit_trap(curr, trap);

        switch ( nsret )
        {
        case NESTEDHVM_VMEXIT_DONE:
        case NESTEDHVM_VMEXIT_ERROR: /* L1 guest will crash L2 guest */
            return;
        case NESTEDHVM_VMEXIT_HOST:
        case NESTEDHVM_VMEXIT_CONTINUE:
        case NESTEDHVM_VMEXIT_FATALERROR:
        default:
            gdprintk(XENLOG_ERR, "unexpected nestedhvm error %i\n", nsret);
            return;
        }
    }

    hvm_funcs.inject_trap(trap);
}

void hvm_inject_hw_exception(unsigned int trapnr, int errcode)
{
    struct hvm_trap trap = {
        .vector = trapnr,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode };
    hvm_inject_trap(&trap);
}

void hvm_inject_page_fault(int errcode, unsigned long cr2)
{
    struct hvm_trap trap = {
        .vector = TRAP_page_fault,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode,
        .cr2 = cr2 };
    hvm_inject_trap(&trap);
}

int hvm_hap_nested_page_fault(paddr_t gpa,
                              bool_t gla_valid,
                              unsigned long gla,
                              bool_t access_r,
                              bool_t access_w,
                              bool_t access_x)
{
    unsigned long gfn = gpa >> PAGE_SHIFT;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    mfn_t mfn;
    struct vcpu *v = current;
    struct p2m_domain *p2m;
    int rc, fall_through = 0, paged = 0;
    int sharing_enomem = 0;
    mem_event_request_t *req_ptr = NULL;

    /* On Nested Virtualization, walk the guest page table.
     * If this succeeds, all is fine.
     * If this fails, inject a nested page fault into the guest.
     */
    if ( nestedhvm_enabled(v->domain)
        && nestedhvm_vcpu_in_guestmode(v)
        && nestedhvm_paging_mode_hap(v) )
    {
        int rv;

        /* The vcpu is in guest mode and the l1 guest
         * uses hap. That means 'gpa' is in l2 guest
         * physical address space.
         * Fix the nested p2m or inject nested page fault
         * into l1 guest if not fixable. The algorithm is
         * the same as for shadow paging.
         */
        rv = nestedhvm_hap_nested_page_fault(v, &gpa,
                                             access_r, access_w, access_x);
        switch (rv) {
        case NESTEDHVM_PAGEFAULT_DONE:
        case NESTEDHVM_PAGEFAULT_RETRY:
            return 1;
        case NESTEDHVM_PAGEFAULT_L1_ERROR:
            /* An error occured while translating gpa from
             * l2 guest address to l1 guest address. */
            return 0;
        case NESTEDHVM_PAGEFAULT_INJECT:
            return -1;
        case NESTEDHVM_PAGEFAULT_MMIO:
            if ( !handle_mmio() )
                hvm_inject_hw_exception(TRAP_gp_fault, 0);
            return 1;
        case NESTEDHVM_PAGEFAULT_L0_ERROR:
            /* gpa is now translated to l1 guest address, update gfn. */
            gfn = gpa >> PAGE_SHIFT;
            break;
        }
    }

    /* For the benefit of 32-bit WinXP (& older Windows) on AMD CPUs,
     * a fast path for LAPIC accesses, skipping the p2m lookup. */
    if ( !nestedhvm_vcpu_in_guestmode(v)
         && is_hvm_vcpu(v)
         && gfn == PFN_DOWN(vlapic_base_address(vcpu_vlapic(v))) )
    {
        if ( !handle_mmio() )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out;
    }

    p2m = p2m_get_hostp2m(v->domain);
    mfn = get_gfn_type_access(p2m, gfn, &p2mt, &p2ma, 
                              P2M_ALLOC | (access_w ? P2M_UNSHARE : 0), NULL);

    /* Check access permissions first, then handle faults */
    if ( mfn_x(mfn) != INVALID_MFN )
    {
        int violation = 0;
        /* If the access is against the permissions, then send to mem_event */
        switch (p2ma) 
        {
        case p2m_access_n:
        case p2m_access_n2rwx:
        default:
            violation = access_r || access_w || access_x;
            break;
        case p2m_access_r:
            violation = access_w || access_x;
            break;
        case p2m_access_w:
            violation = access_r || access_x;
            break;
        case p2m_access_x:
            violation = access_r || access_w;
            break;
        case p2m_access_rx:
        case p2m_access_rx2rw:
            violation = access_w;
            break;
        case p2m_access_wx:
            violation = access_r;
            break;
        case p2m_access_rw:
            violation = access_x;
            break;
        case p2m_access_rwx:
            break;
        }

        if ( violation )
        {
            if ( p2m_mem_access_check(gpa, gla_valid, gla, access_r, 
                                        access_w, access_x, &req_ptr) )
            {
                fall_through = 1;
            } else {
                /* Rights not promoted, vcpu paused, work here is done */
                rc = 1;
                goto out_put_gfn;
            }
        }
    }

    /*
     * If this GFN is emulated MMIO or marked as read-only, pass the fault
     * to the mmio handler.
     */
    if ( (p2mt == p2m_mmio_dm) || 
         (access_w && (p2mt == p2m_ram_ro)) )
    {
        put_gfn(p2m->domain, gfn);

        rc = 0;
        if ( unlikely(is_pvh_vcpu(v)) )
            goto out;

        if ( !handle_mmio() )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out;
    }

    /* Check if the page has been paged out */
    if ( p2m_is_paged(p2mt) || (p2mt == p2m_ram_paging_out) )
        paged = 1;

    /* Mem sharing: unshare the page and try again */
    if ( access_w && (p2mt == p2m_ram_shared) )
    {
        ASSERT(!p2m_is_nestedp2m(p2m));
        sharing_enomem = 
            (mem_sharing_unshare_page(p2m->domain, gfn, 0) < 0);
        rc = 1;
        goto out_put_gfn;
    }
 
    /* Spurious fault? PoD and log-dirty also take this path. */
    if ( p2m_is_ram(p2mt) )
    {
        /*
         * Page log dirty is always done with order 0. If this mfn resides in
         * a large page, we do not change other pages type within that large
         * page.
         */
        if ( access_w )
        {
            paging_mark_dirty(v->domain, mfn_x(mfn));
            p2m_change_type(v->domain, gfn, p2m_ram_logdirty, p2m_ram_rw);
        }
        rc = 1;
        goto out_put_gfn;
    }

    /* Shouldn't happen: Maybe the guest was writing to a r/o grant mapping? */
    if ( access_w && (p2mt == p2m_grant_map_ro) )
    {
        gdprintk(XENLOG_WARNING,
                 "trying to write to read-only grant mapping\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out_put_gfn;
    }

    /* If we fell through, the vcpu will retry now that access restrictions have
     * been removed. It may fault again if the p2m entry type still requires so.
     * Otherwise, this is an error condition. */
    rc = fall_through;

out_put_gfn:
    put_gfn(p2m->domain, gfn);
out:
    /* All of these are delayed until we exit, since we might 
     * sleep on event ring wait queues, and we must not hold
     * locks in such circumstance */
    if ( paged )
        p2m_mem_paging_populate(v->domain, gfn);
    if ( sharing_enomem )
    {
        int rv;
        if ( (rv = mem_sharing_notify_enomem(v->domain, gfn, 1)) < 0 )
        {
            gdprintk(XENLOG_ERR, "Domain %hu attempt to unshare "
                     "gfn %lx, ENOMEM and no helper (rc %d)\n",
                        v->domain->domain_id, gfn, rv);
            /* Crash the domain */
            rc = 0;
        }
    }
    if ( req_ptr )
    {
        mem_access_send_req(v->domain, req_ptr);
        xfree(req_ptr);
    }
    return rc;
}

int hvm_handle_xsetbv(u32 index, u64 new_bv)
{
    struct segment_register sreg;

    hvm_get_segment_register(current, x86_seg_ss, &sreg);
    if ( sreg.attr.fields.dpl != 0 )
        goto err;

    if ( handle_xsetbv(index, new_bv) )
        goto err;

    return 0;
err:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return -1;
}

int hvm_set_efer(uint64_t value)
{
    struct vcpu *v = current;
    uint64_t efer_validbits;

    value &= ~EFER_LMA;

    efer_validbits = EFER_FFXSE | EFER_LMSLE | EFER_LME | EFER_NX | EFER_SCE;
    if ( !hvm_efer_valid(v->domain, value, efer_validbits) )
    {
        gdprintk(XENLOG_WARNING, "Trying to set reserved bit in "
                 "EFER: %#"PRIx64"\n", value);
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return X86EMUL_EXCEPTION;
    }

    if ( ((value ^ v->arch.hvm_vcpu.guest_efer) & EFER_LME) &&
         hvm_paging_enabled(v) )
    {
        gdprintk(XENLOG_WARNING,
                 "Trying to change EFER.LME with paging enabled\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return X86EMUL_EXCEPTION;
    }

    if ( nestedhvm_enabled(v->domain) && cpu_has_svm &&
       ((value & EFER_SVME) == 0 ) &&
       ((value ^ v->arch.hvm_vcpu.guest_efer) & EFER_SVME) )
    {
        /* Cleared EFER.SVME: Flush all nestedp2m tables */
        p2m_flush_nestedp2m(v->domain);
        nestedhvm_vcpu_reset(v);
    }

    value |= v->arch.hvm_vcpu.guest_efer & EFER_LMA;
    v->arch.hvm_vcpu.guest_efer = value;
    hvm_update_guest_efer(v);

    return X86EMUL_OKAY;
}

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
}

int hvm_mov_to_cr(unsigned int cr, unsigned int gpr)
{
    struct vcpu *curr = current;
    unsigned long val, *reg;

    if ( (reg = decode_register(gpr, guest_cpu_user_regs(), 0)) == NULL )
    {
        gdprintk(XENLOG_ERR, "invalid gpr: %u\n", gpr);
        goto exit_and_crash;
    }

    val = *reg;
    HVMTRACE_LONG_2D(CR_WRITE, cr, TRC_PAR_LONG(val));
    HVM_DBG_LOG(DBG_LEVEL_1, "CR%u, value = %lx", cr, val);

    switch ( cr )
    {
    case 0:
        return hvm_set_cr0(val);

    case 3:
        return hvm_set_cr3(val);

    case 4:
        return hvm_set_cr4(val);

    case 8:
        vlapic_set_reg(vcpu_vlapic(curr), APIC_TASKPRI, ((val & 0x0f) << 4));
        break;

    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        goto exit_and_crash;
    }

    return X86EMUL_OKAY;

 exit_and_crash:
    domain_crash(curr->domain);
    return X86EMUL_UNHANDLEABLE;
}

int hvm_mov_from_cr(unsigned int cr, unsigned int gpr)
{
    struct vcpu *curr = current;
    unsigned long val = 0, *reg;

    if ( (reg = decode_register(gpr, guest_cpu_user_regs(), 0)) == NULL )
    {
        gdprintk(XENLOG_ERR, "invalid gpr: %u\n", gpr);
        goto exit_and_crash;
    }

    switch ( cr )
    {
    case 0:
    case 2:
    case 3:
    case 4:
        val = curr->arch.hvm_vcpu.guest_cr[cr];
        break;
    case 8:
        val = (vlapic_get_reg(vcpu_vlapic(curr), APIC_TASKPRI) & 0xf0) >> 4;
        break;
    default:
        gdprintk(XENLOG_ERR, "invalid cr: %u\n", cr);
        goto exit_and_crash;
    }

    *reg = val;
    HVMTRACE_LONG_2D(CR_READ, cr, TRC_PAR_LONG(val));
    HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR%u, value = %lx", cr, val);

    return X86EMUL_OKAY;

 exit_and_crash:
    domain_crash(curr->domain);
    return X86EMUL_UNHANDLEABLE;
}

void hvm_shadow_handle_cd(struct vcpu *v, unsigned long value)
{
    if ( value & X86_CR0_CD )
    {
        /* Entering no fill cache mode. */
        spin_lock(&v->domain->arch.hvm_domain.uc_lock);
        v->arch.hvm_vcpu.cache_mode = NO_FILL_CACHE_MODE;

        if ( !v->domain->arch.hvm_domain.is_in_uc_mode )
        {
            domain_pause_nosync(v->domain);

            /* Flush physical caches. */
            on_each_cpu(local_flush_cache, NULL, 1);
            hvm_set_uc_mode(v, 1);

            domain_unpause(v->domain);
        }
        spin_unlock(&v->domain->arch.hvm_domain.uc_lock);
    }
    else if ( !(value & X86_CR0_CD) &&
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

static void hvm_update_cr(struct vcpu *v, unsigned int cr, unsigned long value)
{
    v->arch.hvm_vcpu.guest_cr[cr] = value;
    nestedhvm_set_cr(v, cr, value);
    hvm_update_guest_cr(v, cr);
}

int hvm_set_cr0(unsigned long value)
{
    struct vcpu *v = current;
    unsigned long gfn, old_value = v->arch.hvm_vcpu.guest_cr[0];
    struct page_info *page;

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

    if ( !nestedhvm_vmswitch_in_progress(v) &&
         (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PG )
        goto gpf;

    /* A pvh is not expected to change to real mode. */
    if ( is_pvh_vcpu(v)
         && (value & (X86_CR0_PE | X86_CR0_PG)) != (X86_CR0_PG | X86_CR0_PE) )
    {
        printk(XENLOG_G_WARNING
               "PVH attempting to turn off PE/PG. CR0:%lx\n", value);
        goto gpf;
    }

    if ( (value & X86_CR0_PG) && !(old_value & X86_CR0_PG) )
    {
        if ( v->arch.hvm_vcpu.guest_efer & EFER_LME )
        {
            if ( !(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PAE) &&
                 !nestedhvm_vmswitch_in_progress(v) )
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
            page = get_page_from_gfn(v->domain, gfn, NULL, P2M_ALLOC);
            if ( !page )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value = %lx\n",
                         v->arch.hvm_vcpu.guest_cr[3]);
                domain_crash(v->domain);
                return X86EMUL_UNHANDLEABLE;
            }

            /* Now arch.guest_table points to machine physical. */
            v->arch.guest_table = pagetable_from_page(page);

            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                        v->arch.hvm_vcpu.guest_cr[3], page_to_mfn(page));
        }
    }
    else if ( !(value & X86_CR0_PG) && (old_value & X86_CR0_PG) )
    {
        if ( hvm_pcid_enabled(v) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Guest attempts to clear CR0.PG "
                        "while CR4.PCIDE=1");
            goto gpf;
        }

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

    /*
     * When cr0.cd setting
     * 1. For guest w/o VT-d, and for guest with VT-d but snooped, Xen need not
     * do anything, since hardware snoop mechanism has ensured cache coherency;
     * 2. For guest with VT-d but non-snooped, cache coherency cannot be
     * guaranteed by h/w so need emulate UC memory type to guest.
     */
    if ( ((value ^ old_value) & X86_CR0_CD) &&
           has_arch_pdevs(v->domain) &&
           iommu_enabled && !iommu_snoop &&
           hvm_funcs.handle_cd )
        hvm_funcs.handle_cd(v, value);

    hvm_update_cr(v, 0, value);
    hvm_memory_event_cr0(value, old_value);

    if ( (value ^ old_value) & X86_CR0_PG ) {
        if ( !nestedhvm_vmswitch_in_progress(v) && nestedhvm_vcpu_in_guestmode(v) )
            paging_update_nestedmode(v);
        else
            paging_update_paging_modes(v);
    }

    return X86EMUL_OKAY;

 gpf:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

int hvm_set_cr3(unsigned long value)
{
    struct vcpu *v = current;
    struct page_info *page;
    unsigned long old;

    if ( hvm_paging_enabled(v) && !paging_mode_hap(v->domain) &&
         (value != v->arch.hvm_vcpu.guest_cr[3]) )
    {
        /* Shadow-mode CR3 change. Check PDBR and update refcounts. */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
        page = get_page_from_gfn(v->domain, value >> PAGE_SHIFT,
                                 NULL, P2M_ALLOC);
        if ( !page )
            goto bad_cr3;

        put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_from_page(page);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx", value);
    }

    old=v->arch.hvm_vcpu.guest_cr[3];
    v->arch.hvm_vcpu.guest_cr[3] = value;
    paging_update_cr3(v);
    hvm_memory_event_cr3(value, old);
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

    if ( value & HVM_CR4_GUEST_RESERVED_BITS(v, 0) )
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

    if ( (value & X86_CR4_PCIDE) && !(old_cr & X86_CR4_PCIDE) &&
         (!hvm_long_mode_enabled(v) ||
          (v->arch.hvm_vcpu.guest_cr[3] & 0xfff)) )
    {
        HVM_DBG_LOG(DBG_LEVEL_1, "Guest attempts to change CR4.PCIDE from "
                    "0 to 1 while either EFER.LMA=0 or CR3[11:0]!=000H");
        goto gpf;
    }

    hvm_update_cr(v, 4, value);
    hvm_memory_event_cr4(value, old_cr);

    /*
     * Modifying CR4.{PSE,PAE,PGE,SMEP}, or clearing CR4.PCIDE
     * invalidate all TLB entries.
     */
    if ( ((old_cr ^ value) &
          (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE | X86_CR4_SMEP)) ||
         (!(value & X86_CR4_PCIDE) && (old_cr & X86_CR4_PCIDE)) )
    {
        if ( !nestedhvm_vmswitch_in_progress(v) && nestedhvm_vcpu_in_guestmode(v) )
            paging_update_nestedmode(v);
        else
            paging_update_paging_modes(v);
    }

    return X86EMUL_OKAY;

 gpf:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
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
    unsigned long addr = offset, last_byte;

    if ( !(current->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) )
    {
        /*
         * REAL MODE: Don't bother with segment access checks.
         * Certain of them are not done in native real mode anyway.
         */
        addr = (uint32_t)(addr + reg->base);
        last_byte = (uint32_t)addr + bytes - 1;
        if ( last_byte < addr )
            return 0;
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
                return 0; /* execute-only code segment */
            break;
        case hvm_access_write:
            if ( (reg->attr.fields.type & 0xa) != 0x2 )
                return 0; /* not a writable data segment */
            break;
        default:
            break;
        }

        last_byte = (uint32_t)offset + bytes - 1;

        /* Is this a grows-down data segment? Special limit check if so. */
        if ( (reg->attr.fields.type & 0xc) == 0x4 )
        {
            /* Is upper limit 0xFFFF or 0xFFFFFFFF? */
            if ( !reg->attr.fields.db )
                last_byte = (uint16_t)last_byte;

            /* Check first byte and last byte against respective bounds. */
            if ( (offset <= reg->limit) || (last_byte < offset) )
                return 0;
        }
        else if ( (last_byte > reg->limit) || (last_byte < offset) )
            return 0; /* last byte is beyond limit or wraps 0xFFFFFFFF */

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

        last_byte = addr + bytes - 1;
        if ( !is_canonical_address(addr) || last_byte < addr ||
             !is_canonical_address(last_byte) )
            return 0;
    }

    *linear_addr = addr;
    return 1;
}

/* On non-NULL return, we leave this function holding an additional 
 * ref on the underlying mfn, if any */
static void *__hvm_map_guest_frame(unsigned long gfn, bool_t writable,
                                   bool_t permanent)
{
    void *map;
    p2m_type_t p2mt;
    struct page_info *page;
    struct domain *d = current->domain;

    page = get_page_from_gfn(d, gfn, &p2mt,
                             writable ? P2M_UNSHARE : P2M_ALLOC);
    if ( (p2m_is_shared(p2mt) && writable) || !page )
    {
        if ( page )
            put_page(page);
        return NULL;
    }
    if ( p2m_is_paging(p2mt) )
    {
        put_page(page);
        p2m_mem_paging_populate(d, gfn);
        return NULL;
    }

    if ( writable )
        paging_mark_dirty(d, page_to_mfn(page));

    if ( !permanent )
        return __map_domain_page(page);

    map = __map_domain_page_global(page);
    if ( !map )
        put_page(page);

    return map;
}

void *hvm_map_guest_frame_rw(unsigned long gfn, bool_t permanent)
{
    return __hvm_map_guest_frame(gfn, 1, permanent);
}

void *hvm_map_guest_frame_ro(unsigned long gfn, bool_t permanent)
{
    return __hvm_map_guest_frame(gfn, 0, permanent);
}

void hvm_unmap_guest_frame(void *p, bool_t permanent)
{
    unsigned long mfn;

    if ( !p )
        return;

    mfn = domain_page_map_to_mfn(p);

    if ( !permanent )
        unmap_domain_page(p);
    else
        unmap_domain_page_global(p);

    put_page(mfn_to_page(mfn));
}

static void *hvm_map_entry(unsigned long va)
{
    unsigned long gfn;
    uint32_t pfec;
    char *v;

    if ( ((va & ~PAGE_MASK) + 8) > PAGE_SIZE )
    {
        gdprintk(XENLOG_ERR, "Descriptor table entry "
                 "straddles page boundary\n");
        goto fail;
    }

    /*
     * We're mapping on behalf of the segment-load logic, which might write
     * the accessed flags in the descriptors (in 32-bit mode), but we still
     * treat it as a kernel-mode read (i.e. no access checks).
     */
    pfec = PFEC_page_present;
    gfn = paging_gva_to_gfn(current, va, &pfec);
    if ( (pfec == PFEC_page_paged) || (pfec == PFEC_page_shared) )
        goto fail;

    v = hvm_map_guest_frame_rw(gfn, 0);
    if ( v == NULL )
        goto fail;

    return v + (va & ~PAGE_MASK);

 fail:
    domain_crash(current->domain);
    return NULL;
}

static void hvm_unmap_entry(void *p)
{
    hvm_unmap_guest_frame(p, 0);
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
        if ( !(desc.b & _SEGMENT_P) )
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
            if ( !(desc.b & _SEGMENT_CODE) )
                goto unmap_and_fail;
            /* Non-conforming segment: check DPL against RPL. */
            if ( !(desc.b & _SEGMENT_EC) && (dpl != rpl) )
                goto unmap_and_fail;
            break;
        case x86_seg_ss:
            /* Writable data segment? */
            if ( (desc.b & (_SEGMENT_CODE|_SEGMENT_WR)) != _SEGMENT_WR )
                goto unmap_and_fail;
            if ( (dpl != cpl) || (dpl != rpl) )
                goto unmap_and_fail;
            break;
        case x86_seg_ldtr:
            /* LDT system segment? */
            if ( (desc.b & _SEGMENT_TYPE) != (2u<<8) )
                goto unmap_and_fail;
            goto skip_accessed_flag;
        default:
            /* Readable code or data segment? */
            if ( (desc.b & (_SEGMENT_CODE|_SEGMENT_WR)) == _SEGMENT_CODE )
                goto unmap_and_fail;
            /*
             * Data or non-conforming code segment:
             * check DPL against RPL and CPL.
             */
            if ( ((desc.b & (_SEGMENT_EC|_SEGMENT_CODE)) !=
                  (_SEGMENT_EC|_SEGMENT_CODE))
                 && ((dpl < cpl) || (dpl < rpl)) )
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
    hvm_inject_hw_exception(fault_type, sel & 0xfffc);
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
        hvm_inject_hw_exception((taskswitch_reason == TSW_iret) ?
                             TRAP_invalid_tss : TRAP_gp_fault,
                             tss_sel & 0xfff8);
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
        hvm_inject_hw_exception(TRAP_no_segment, tss_sel & 0xfff8);
        goto out;
    }

    if ( tr.attr.fields.type != ((taskswitch_reason == TSW_iret) ? 0xb : 0x9) )
    {
        hvm_inject_hw_exception(
            (taskswitch_reason == TSW_iret) ? TRAP_invalid_tss : TRAP_gp_fault,
            tss_sel & 0xfff8);
        goto out;
    }

    if ( tr.limit < (sizeof(tss)-1) )
    {
        hvm_inject_hw_exception(TRAP_invalid_tss, tss_sel & 0xfff8);
        goto out;
    }

    rc = hvm_copy_from_guest_virt(
        &tss, prev_tr.base, sizeof(tss), PFEC_page_present);
    if ( rc != HVMCOPY_okay )
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
    if ( rc != HVMCOPY_okay )
        goto out;

    rc = hvm_copy_from_guest_virt(
        &tss, tr.base, sizeof(tss), PFEC_page_present);
    /*
     * Note: The HVMCOPY_gfn_shared case could be optimised, if the callee
     * functions knew we want RO access.
     */
    if ( rc != HVMCOPY_okay )
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
    else if ( rc != HVMCOPY_okay )
        goto out;

    if ( (tss.trace & 1) && !exn_raised )
        hvm_inject_hw_exception(TRAP_debug, tss_sel & 0xfff8);

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
    unsigned long gfn;
    struct page_info *page;
    p2m_type_t p2mt;
    char *p;
    int count, todo = size;

    /*
     * XXX Disable for 4.1.0: PV-on-HVM drivers will do grant-table ops
     * such as query_size. Grant-table code currently does copy_to/from_guest
     * accesses under the big per-domain lock, which this test would disallow.
     * The test is not needed until we implement sleeping-on-waitqueue when
     * we access a paged-out frame, and that's post 4.1.0 now.
     */
#if 0
    /*
     * If the required guest memory is paged out, this function may sleep.
     * Hence we bail immediately if called from atomic context.
     */
    if ( in_atomic() )
        return HVMCOPY_unhandleable;
#endif

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
                    hvm_inject_page_fault(pfec, addr);
                return HVMCOPY_bad_gva_to_gfn;
            }
        }
        else
        {
            gfn = addr >> PAGE_SHIFT;
        }

        /* For the benefit of 32-bit WinXP (& older Windows) on AMD CPUs,
         * a fast path for LAPIC accesses, skipping the p2m lookup. */
        if ( !nestedhvm_vcpu_in_guestmode(curr)
             && gfn == PFN_DOWN(vlapic_base_address(vcpu_vlapic(curr))) )
            return HVMCOPY_bad_gfn_to_mfn;

        page = get_page_from_gfn(curr->domain, gfn, &p2mt, P2M_UNSHARE);

        if ( !page )
            return HVMCOPY_bad_gfn_to_mfn;

        if ( p2m_is_paging(p2mt) )
        {
            put_page(page);
            p2m_mem_paging_populate(curr->domain, gfn);
            return HVMCOPY_gfn_paged_out;
        }
        if ( p2m_is_shared(p2mt) )
        {
            put_page(page);
            return HVMCOPY_gfn_shared;
        }
        if ( p2m_is_grant(p2mt) )
        {
            put_page(page);
            return HVMCOPY_unhandleable;
        }

        p = (char *)__map_domain_page(page) + (addr & ~PAGE_MASK);

        if ( flags & HVMCOPY_to_guest )
        {
            if ( p2mt == p2m_ram_ro )
            {
                static unsigned long lastpage;
                if ( xchg(&lastpage, gfn) != gfn )
                    gdprintk(XENLOG_DEBUG, "guest attempted write to read-only"
                             " memory page. gfn=%#lx, mfn=%#lx\n",
                             gfn, page_to_mfn(page));
            }
            else
            {
                memcpy(p, buf, count);
                paging_mark_dirty(curr->domain, page_to_mfn(page));
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
        put_page(page);
    }

    return HVMCOPY_okay;
}

static enum hvm_copy_result __hvm_clear(paddr_t addr, int size)
{
    struct vcpu *curr = current;
    unsigned long gfn;
    struct page_info *page;
    p2m_type_t p2mt;
    char *p;
    int count, todo = size;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;

    /*
     * XXX Disable for 4.1.0: PV-on-HVM drivers will do grant-table ops
     * such as query_size. Grant-table code currently does copy_to/from_guest
     * accesses under the big per-domain lock, which this test would disallow.
     * The test is not needed until we implement sleeping-on-waitqueue when
     * we access a paged-out frame, and that's post 4.1.0 now.
     */
#if 0
    /*
     * If the required guest memory is paged out, this function may sleep.
     * Hence we bail immediately if called from atomic context.
     */
    if ( in_atomic() )
        return HVMCOPY_unhandleable;
#endif

    while ( todo > 0 )
    {
        count = min_t(int, PAGE_SIZE - (addr & ~PAGE_MASK), todo);

        gfn = paging_gva_to_gfn(curr, addr, &pfec);
        if ( gfn == INVALID_GFN )
        {
            if ( pfec == PFEC_page_paged )
                return HVMCOPY_gfn_paged_out;
            if ( pfec == PFEC_page_shared )
                return HVMCOPY_gfn_shared;
            return HVMCOPY_bad_gva_to_gfn;
        }

        page = get_page_from_gfn(curr->domain, gfn, &p2mt, P2M_UNSHARE);

        if ( !page )
            return HVMCOPY_bad_gfn_to_mfn;

        if ( p2m_is_paging(p2mt) )
        {
            put_page(page);
            p2m_mem_paging_populate(curr->domain, gfn);
            return HVMCOPY_gfn_paged_out;
        }
        if ( p2m_is_shared(p2mt) )
        {
            put_page(page);
            return HVMCOPY_gfn_shared;
        }
        if ( p2m_is_grant(p2mt) )
        {
            put_page(page);
            return HVMCOPY_unhandleable;
        }

        p = (char *)__map_domain_page(page) + (addr & ~PAGE_MASK);

        if ( p2mt == p2m_ram_ro )
        {
            static unsigned long lastpage;
            if ( xchg(&lastpage, gfn) != gfn )
                gdprintk(XENLOG_DEBUG, "guest attempted write to read-only"
                        " memory page. gfn=%#lx, mfn=%#lx\n",
                         gfn, page_to_mfn(page));
        }
        else
        {
            memset(p, 0x00, count);
            paging_mark_dirty(curr->domain, page_to_mfn(page));
        }

        unmap_domain_page(p);

        addr += count;
        todo -= count;
        put_page(page);
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
    if ( hvm_nx_enabled(current) || hvm_smep_enabled(current) )
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
    if ( hvm_nx_enabled(current) || hvm_smep_enabled(current) )
        pfec |= PFEC_insn_fetch;
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

unsigned long copy_to_user_hvm(void *to, const void *from, unsigned int len)
{
    int rc;

    if ( !current->arch.hvm_vcpu.hcall_64bit &&
         is_compat_arg_xlat_range(to, len) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_to_guest_virt_nofault((unsigned long)to, (void *)from,
                                        len, 0);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long clear_user_hvm(void *to, unsigned int len)
{
    int rc;

    if ( !current->arch.hvm_vcpu.hcall_64bit &&
         is_compat_arg_xlat_range(to, len) )
    {
        memset(to, 0x00, len);
        return 0;
    }

    rc = __hvm_clear((unsigned long)to, len);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len)
{
    int rc;

    if ( !current->arch.hvm_vcpu.hcall_64bit &&
         is_compat_arg_xlat_range(from, len) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_from_guest_virt_nofault(to, (unsigned long)from, len, 0);
    return rc ? len : 0; /* fake a copy_from_user() return code */
}

void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned int count, dummy = 0;

    if ( !eax )
        eax = &dummy;
    if ( !ebx )
        ebx = &dummy;
    if ( !ecx )
        ecx = &dummy;
    count = *ecx;
    if ( !edx )
        edx = &dummy;

    if ( cpuid_viridian_leaves(input, eax, ebx, ecx, edx) )
        return;

    if ( cpuid_hypervisor_leaves(input, count, eax, ebx, ecx, edx) )
        return;

    domain_cpuid(d, input, count, eax, ebx, ecx, edx);

    switch ( input )
    {
        unsigned int sub_leaf, _eax, _ebx, _ecx, _edx;

    case 0x1:
        /* Fix up VLAPIC details. */
        *ebx &= 0x00FFFFFFu;
        *ebx |= (v->vcpu_id * 2) << 24;
        if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
            __clear_bit(X86_FEATURE_APIC & 31, edx);

        /* Fix up OSXSAVE. */
        if ( cpu_has_xsave )
            *ecx |= (v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_OSXSAVE) ?
                     cpufeat_mask(X86_FEATURE_OSXSAVE) : 0;

        /* Don't expose PCID to non-hap hvm. */
        if ( !hap_enabled(d) )
            *ecx &= ~cpufeat_mask(X86_FEATURE_PCID);

        /* Only provide PSE36 when guest runs in 32bit PAE or in long mode */
        if ( !(hvm_pae_enabled(v) || hvm_long_mode_enabled(v)) )
            *edx &= ~cpufeat_mask(X86_FEATURE_PSE36);
        break;
    case 0x7:
        if ( (count == 0) && !cpu_has_smep )
            *ebx &= ~cpufeat_mask(X86_FEATURE_SMEP);

        /* Don't expose INVPCID to non-hap hvm. */
        if ( (count == 0) && !hap_enabled(d) )
            *ebx &= ~cpufeat_mask(X86_FEATURE_INVPCID);
        break;
    case 0xb:
        /* Fix the x2APIC identifier. */
        *edx = v->vcpu_id * 2;
        break;
    case 0xd:
        /* EBX value of main leaf 0 depends on enabled xsave features */
        if ( count == 0 && v->arch.xcr0 ) 
        {
            /* reset EBX to default value first */
            *ebx = XSTATE_AREA_MIN_SIZE; 
            for ( sub_leaf = 2; sub_leaf < 63; sub_leaf++ )
            {
                if ( !(v->arch.xcr0 & (1ULL << sub_leaf)) )
                    continue;
                domain_cpuid(d, input, sub_leaf, &_eax, &_ebx, &_ecx, 
                             &_edx);
                if ( (_eax + _ebx) > *ebx )
                    *ebx = _eax + _ebx;
            }
        }
        break;

    case 0x80000001:
        /* We expose RDTSCP feature to guest only when
           tsc_mode == TSC_MODE_DEFAULT and host_tsc_is_safe() returns 1 */
        if ( d->arch.tsc_mode != TSC_MODE_DEFAULT ||
             !host_tsc_is_safe() )
            *edx &= ~cpufeat_mask(X86_FEATURE_RDTSCP);
        /* Hide 1GB-superpage feature if we can't emulate it. */
        if (!hvm_pse1gb_supported(d))
            *edx &= ~cpufeat_mask(X86_FEATURE_PAGE1GB);
        /* Only provide PSE36 when guest runs in 32bit PAE or in long mode */
        if ( !(hvm_pae_enabled(v) || hvm_long_mode_enabled(v)) )
            *edx &= ~cpufeat_mask(X86_FEATURE_PSE36);
        break;

    case 0x80000008:
        count = cpuid_eax(0x80000008);
        count = (count >> 16) & 0xff ?: count & 0xff;
        if ( (*eax & 0xff) > count )
            *eax = (*eax & ~0xff) | count;

        hvm_cpuid(1, NULL, NULL, NULL, &_edx);
        count = _edx & (cpufeat_mask(X86_FEATURE_PAE) |
                        cpufeat_mask(X86_FEATURE_PSE36)) ? 36 : 32;
        if ( (*eax & 0xff) < count )
            *eax = (*eax & ~0xff) | count;

        hvm_cpuid(0x80000001, NULL, NULL, NULL, &_edx);
        *eax = (*eax & ~0xffff00) | (_edx & cpufeat_mask(X86_FEATURE_LM)
                                     ? 0x3000 : 0x2000);
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

    HVMTRACE_2D(RDTSC, regs->eax, regs->edx);
}

int hvm_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    uint64_t *var_range_base, *fixed_range_base;
    bool_t mtrr;
    unsigned int edx, index;
    int ret = X86EMUL_OKAY;

    var_range_base = (uint64_t *)v->arch.hvm_vcpu.mtrr.var_ranges;
    fixed_range_base = (uint64_t *)v->arch.hvm_vcpu.mtrr.fixed_ranges;

    hvm_cpuid(1, NULL, NULL, NULL, &edx);
    mtrr = !!(edx & cpufeat_mask(X86_FEATURE_MTRR));

    switch ( msr )
    {
    case MSR_EFER:
        *msr_content = v->arch.hvm_vcpu.guest_efer;
        break;

    case MSR_IA32_TSC:
        *msr_content = hvm_get_guest_tsc(v);
        break;

    case MSR_IA32_TSC_ADJUST:
        *msr_content = hvm_get_guest_tsc_adjust(v);
        break;

    case MSR_TSC_AUX:
        *msr_content = hvm_msr_tsc_aux(v);
        break;

    case MSR_IA32_APICBASE:
        *msr_content = vcpu_vlapic(v)->hw.apic_base_msr;
        break;

    case MSR_IA32_APICBASE_MSR ... MSR_IA32_APICBASE_MSR + 0xff:
        if ( hvm_x2apic_msr_read(v, msr, msr_content) )
            goto gp_fault;
        break;

    case MSR_IA32_TSC_DEADLINE:
        *msr_content = vlapic_tdt_msr_get(vcpu_vlapic(v));
        break;

    case MSR_IA32_CR_PAT:
        hvm_get_guest_pat(v, msr_content);
        break;

    case MSR_MTRRcap:
        if ( !mtrr )
            goto gp_fault;
        *msr_content = v->arch.hvm_vcpu.mtrr.mtrr_cap;
        break;
    case MSR_MTRRdefType:
        if ( !mtrr )
            goto gp_fault;
        *msr_content = v->arch.hvm_vcpu.mtrr.def_type
                        | (v->arch.hvm_vcpu.mtrr.enabled << 10);
        break;
    case MSR_MTRRfix64K_00000:
        if ( !mtrr )
            goto gp_fault;
        *msr_content = fixed_range_base[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix16K_80000;
        *msr_content = fixed_range_base[index + 1];
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix4K_C0000;
        *msr_content = fixed_range_base[index + 3];
        break;
    case MSR_IA32_MTRR_PHYSBASE0...MSR_IA32_MTRR_PHYSMASK7:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_IA32_MTRR_PHYSBASE0;
        *msr_content = var_range_base[index];
        break;

    case MSR_K8_ENABLE_C1E:
    case MSR_AMD64_NB_CFG:
         /*
          * These AMD-only registers may be accessed if this HVM guest
          * has been migrated to an Intel host. This fixes a guest crash
          * in this case.
          */
         *msr_content = 0;
         break;

    default:
        if ( (ret = vmce_rdmsr(msr, msr_content)) < 0 )
            goto gp_fault;
        /* If ret == 0 then this is not an MCE MSR, see other MSRs. */
        ret = ((ret == 0)
               ? hvm_funcs.msr_read_intercept(msr, msr_content)
               : X86EMUL_OKAY);
        break;
    }

 out:
    HVMTRACE_3D(MSR_READ, msr,
                (uint32_t)*msr_content, (uint32_t)(*msr_content >> 32));
    return ret;

 gp_fault:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    ret = X86EMUL_EXCEPTION;
    *msr_content = -1ull;
    goto out;
}

int hvm_msr_write_intercept(unsigned int msr, uint64_t msr_content)
{
    struct vcpu *v = current;
    bool_t mtrr;
    unsigned int edx, index;
    int ret = X86EMUL_OKAY;

    HVMTRACE_3D(MSR_WRITE, msr,
               (uint32_t)msr_content, (uint32_t)(msr_content >> 32));

    hvm_cpuid(1, NULL, NULL, NULL, &edx);
    mtrr = !!(edx & cpufeat_mask(X86_FEATURE_MTRR));

    hvm_memory_event_msr(msr, msr_content);

    switch ( msr )
    {
    case MSR_EFER:
        if ( hvm_set_efer(msr_content) )
           return X86EMUL_EXCEPTION;
        break;

    case MSR_IA32_TSC:
        hvm_set_guest_tsc(v, msr_content);
        break;

    case MSR_IA32_TSC_ADJUST:
        hvm_set_guest_tsc_adjust(v, msr_content);
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

    case MSR_IA32_TSC_DEADLINE:
        vlapic_tdt_msr_set(vcpu_vlapic(v), msr_content);
        break;

    case MSR_IA32_APICBASE_MSR ... MSR_IA32_APICBASE_MSR + 0xff:
        if ( hvm_x2apic_msr_write(v, msr, msr_content) )
            goto gp_fault;
        break;

    case MSR_IA32_CR_PAT:
        if ( !hvm_set_guest_pat(v, msr_content) )
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
        index = msr - MSR_MTRRfix16K_80000 + 1;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix4K_C0000 + 3;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_IA32_MTRR_PHYSBASE0...MSR_IA32_MTRR_PHYSMASK7:
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_var_range_msr_set(v->domain, &v->arch.hvm_vcpu.mtrr,
                                     msr, msr_content) )
            goto gp_fault;
        break;

    case MSR_AMD64_NB_CFG:
        /* ignore the write */
        break;

    default:
        if ( (ret = vmce_wrmsr(msr, msr_content)) < 0 )
            goto gp_fault;
        /* If ret == 0 then this is not an MCE MSR, see other MSRs. */
        ret = ((ret == 0)
               ? hvm_funcs.msr_write_intercept(msr, msr_content)
               : X86EMUL_OKAY);
        break;
    }

    return ret;

gp_fault:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

enum hvm_intblk hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack)
{
    unsigned long intr_shadow;

    ASSERT(v == current);

    if ( nestedhvm_enabled(v->domain) ) {
        enum hvm_intblk intr;

        intr = nhvm_interrupt_blocked(v);
        if ( intr != hvm_intblk_none )
            return intr;
    }

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
    case GNTTABOP_get_version:
    case GNTTABOP_copy:
    case GNTTABOP_map_grant_ref:
    case GNTTABOP_unmap_grant_ref:
    case GNTTABOP_swap_grant_ref:
        return 1;
    default:
        /* all other commands need auditing */
        return 0;
    }
}

static long hvm_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop, unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS; /* all other commands need auditing */
    return do_grant_table_op(cmd, uop, count);
}

static long hvm_memory_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc;

    switch ( cmd & MEMOP_CMD_MASK )
    {
    case XENMEM_memory_map:
    case XENMEM_machine_memory_map:
    case XENMEM_machphys_mapping:
        return -ENOSYS;
    case XENMEM_decrease_reservation:
        rc = do_memory_op(cmd, arg);
        current->domain->arch.hvm_domain.qemu_mapcache_invalidate = 1;
        return rc;
    }
    return do_memory_op(cmd, arg);
}

static long hvm_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
    default:
        if ( !is_pvh_vcpu(current) || !is_hardware_domain(current->domain) )
            return -ENOSYS;
        /* fall through */
    case PHYSDEVOP_map_pirq:
    case PHYSDEVOP_unmap_pirq:
    case PHYSDEVOP_eoi:
    case PHYSDEVOP_irq_status_query:
    case PHYSDEVOP_get_free_pirq:
        return do_physdev_op(cmd, arg);

    /* pvh fixme: coming soon */
    case PHYSDEVOP_pirq_eoi_gmfn_v1:
    case PHYSDEVOP_pirq_eoi_gmfn_v2:
        return -ENOSYS;

    }
}

static long hvm_vcpu_op(
    int cmd, int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    case VCPUOP_get_runstate_info:
    case VCPUOP_set_periodic_timer:
    case VCPUOP_stop_periodic_timer:
    case VCPUOP_set_singleshot_timer:
    case VCPUOP_stop_singleshot_timer:
    case VCPUOP_register_vcpu_info:
    case VCPUOP_register_vcpu_time_memory_area:
        rc = do_vcpu_op(cmd, vcpuid, arg);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

typedef unsigned long hvm_hypercall_t(
    unsigned long, unsigned long, unsigned long, unsigned long, unsigned long,
    unsigned long);

#define HYPERCALL(x)                                        \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x

static long hvm_grant_table_op_compat32(unsigned int cmd,
                                        XEN_GUEST_HANDLE_PARAM(void) uop,
                                        unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS;
    return compat_grant_table_op(cmd, uop, count);
}

static long hvm_memory_op_compat32(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc;

    switch ( cmd & MEMOP_CMD_MASK )
    {
    case XENMEM_memory_map:
    case XENMEM_machine_memory_map:
    case XENMEM_machphys_mapping:
        return -ENOSYS;
    case XENMEM_decrease_reservation:
        rc = compat_memory_op(cmd, arg);
        current->domain->arch.hvm_domain.qemu_mapcache_invalidate = 1;
        return rc;
    }
    return compat_memory_op(cmd, arg);
}

static long hvm_vcpu_op_compat32(
    int cmd, int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    case VCPUOP_get_runstate_info:
    case VCPUOP_set_periodic_timer:
    case VCPUOP_stop_periodic_timer:
    case VCPUOP_set_singleshot_timer:
    case VCPUOP_stop_singleshot_timer:
    case VCPUOP_register_vcpu_info:
    case VCPUOP_register_vcpu_time_memory_area:
        rc = compat_vcpu_op(cmd, vcpuid, arg);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

static long hvm_physdev_op_compat32(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
        case PHYSDEVOP_map_pirq:
        case PHYSDEVOP_unmap_pirq:
        case PHYSDEVOP_eoi:
        case PHYSDEVOP_irq_status_query:
        case PHYSDEVOP_get_free_pirq:
            return compat_physdev_op(cmd, arg);
        break;
    default:
            return -ENOSYS;
        break;
    }
}

static hvm_hypercall_t *const hvm_hypercall64_table[NR_hypercalls] = {
    [ __HYPERVISOR_memory_op ] = (hvm_hypercall_t *)hvm_memory_op,
    [ __HYPERVISOR_grant_table_op ] = (hvm_hypercall_t *)hvm_grant_table_op,
    [ __HYPERVISOR_vcpu_op ] = (hvm_hypercall_t *)hvm_vcpu_op,
    [ __HYPERVISOR_physdev_op ] = (hvm_hypercall_t *)hvm_physdev_op,
    HYPERCALL(xen_version),
    HYPERCALL(console_io),
    HYPERCALL(event_channel_op),
    HYPERCALL(sched_op),
    HYPERCALL(set_timer_op),
    HYPERCALL(xsm_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
    HYPERCALL(tmem_op),
    [ __HYPERVISOR_arch_1 ] = (hvm_hypercall_t *)paging_domctl_continuation
};

#define COMPAT_CALL(x)                                        \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) compat_ ## x

static hvm_hypercall_t *const hvm_hypercall32_table[NR_hypercalls] = {
    [ __HYPERVISOR_memory_op ] = (hvm_hypercall_t *)hvm_memory_op_compat32,
    [ __HYPERVISOR_grant_table_op ] = (hvm_hypercall_t *)hvm_grant_table_op_compat32,
    [ __HYPERVISOR_vcpu_op ] = (hvm_hypercall_t *)hvm_vcpu_op_compat32,
    [ __HYPERVISOR_physdev_op ] = (hvm_hypercall_t *)hvm_physdev_op_compat32,
    COMPAT_CALL(xen_version),
    HYPERCALL(console_io),
    HYPERCALL(event_channel_op),
    COMPAT_CALL(sched_op),
    COMPAT_CALL(set_timer_op),
    HYPERCALL(xsm_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
    HYPERCALL(tmem_op),
    [ __HYPERVISOR_arch_1 ] = (hvm_hypercall_t *)paging_domctl_continuation
};

/* PVH 32bitfixme. */
static hvm_hypercall_t *const pvh_hypercall64_table[NR_hypercalls] = {
    HYPERCALL(platform_op),
    HYPERCALL(memory_op),
    HYPERCALL(xen_version),
    HYPERCALL(console_io),
    [ __HYPERVISOR_grant_table_op ]  = (hvm_hypercall_t *)hvm_grant_table_op,
    HYPERCALL(vcpu_op),
    HYPERCALL(mmuext_op),
    HYPERCALL(xsm_op),
    HYPERCALL(sched_op),
    HYPERCALL(event_channel_op),
    [ __HYPERVISOR_physdev_op ]      = (hvm_hypercall_t *)hvm_physdev_op,
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
    [ __HYPERVISOR_arch_1 ] = (hvm_hypercall_t *)paging_domctl_continuation
};

int hvm_do_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct segment_register sreg;
    int mode = hvm_guest_x86_mode(curr);
    uint32_t eax = regs->eax;

    switch ( mode )
    {
    case 8:        
    case 4:
    case 2:
        hvm_get_segment_register(curr, x86_seg_ss, &sreg);
        if ( unlikely(sreg.attr.fields.dpl) )
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

    if ( (eax >= NR_hypercalls) ||
         (is_pvh_vcpu(curr) ? !pvh_hypercall64_table[eax]
                            : !hvm_hypercall32_table[eax]) )
    {
        regs->eax = -ENOSYS;
        return HVM_HCALL_completed;
    }

    curr->arch.hvm_vcpu.hcall_preempted = 0;

    if ( mode == 8 )
    {
        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%u(%lx, %lx, %lx, %lx, %lx, %lx)",
                    eax, regs->rdi, regs->rsi, regs->rdx,
                    regs->r10, regs->r8, regs->r9);

        curr->arch.hvm_vcpu.hcall_64bit = 1;
        if ( is_pvh_vcpu(curr) )
            regs->rax = pvh_hypercall64_table[eax](regs->rdi, regs->rsi,
                                                   regs->rdx, regs->r10,
                                                   regs->r8, regs->r9);
        else
            regs->rax = hvm_hypercall64_table[eax](regs->rdi, regs->rsi,
                                                   regs->rdx, regs->r10,
                                                   regs->r8, regs->r9);
        curr->arch.hvm_vcpu.hcall_64bit = 0;
    }
    else
    {
        ASSERT(!is_pvh_vcpu(curr));   /* PVH 32bitfixme. */

        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%u(%x, %x, %x, %x, %x, %x)", eax,
                    (uint32_t)regs->ebx, (uint32_t)regs->ecx,
                    (uint32_t)regs->edx, (uint32_t)regs->esi,
                    (uint32_t)regs->edi, (uint32_t)regs->ebp);

        regs->eax = hvm_hypercall32_table[eax]((uint32_t)regs->ebx,
                                               (uint32_t)regs->ecx,
                                               (uint32_t)regs->edx,
                                               (uint32_t)regs->esi,
                                               (uint32_t)regs->edi,
                                               (uint32_t)regs->ebp);
    }

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%u -> %lx",
                eax, (unsigned long)regs->eax);

    if ( curr->arch.hvm_vcpu.hcall_preempted )
        return HVM_HCALL_preempted;

    if ( unlikely(curr->domain->arch.hvm_domain.qemu_mapcache_invalidate) &&
         test_and_clear_bool(curr->domain->arch.hvm_domain.
                             qemu_mapcache_invalidate) )
        return HVM_HCALL_invalidate;

    return HVM_HCALL_completed;
}

static void hvm_latch_shinfo_size(struct domain *d)
{
    /*
     * Called from operations which are among the very first executed by
     * PV drivers on initialisation or after save/restore. These are sensible
     * points at which to sample the execution mode of the guest and latch
     * 32- or 64-bit format for shared state.
     */
    if ( current->domain == d )
    {
        d->arch.has_32bit_shinfo = (hvm_guest_x86_mode(current) != 8);
        /*
         * Make sure that the timebase in the shared info structure is correct.
         *
         * If the bit-ness changed we should arguably try to convert the other
         * fields as well, but that's much more problematic (e.g. what do you
         * do if you're going from 64 bit to 32 bit and there's an event
         * channel pending which doesn't exist in the 32 bit version?).  Just
         * setting the wallclock time seems to be sufficient for everything
         * we do, even if it is a bit of a hack.
         */
        update_domain_wallclock_time(d);
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
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_pci_intx_level_t) uop)
{
    struct xen_hvm_set_pci_intx_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.domain > 0) || (op.bus > 0) || (op.device > 31) || (op.intx > 3) )
        return -EINVAL;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_pci_intx_level(XSM_DM_PRIV, d);
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
    struct segment_register reg;
    typeof(v->arch.xsave_area->fpu_sse) *fpu_ctxt = v->arch.fpu_ctxt;

    domain_lock(d);

    if ( v->is_initialised )
        goto out;

    if ( !paging_mode_hap(d) )
    {
        if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_null();
    }

    memset(fpu_ctxt, 0, sizeof(*fpu_ctxt));
    fpu_ctxt->fcw = FCW_RESET;
    fpu_ctxt->mxcsr = MXCSR_DEFAULT;
    if ( v->arch.xsave_area )
        v->arch.xsave_area->xsave_hdr.xstate_bv = XSTATE_FP;

    v->arch.vgc_flags = VGCF_online;
    memset(&v->arch.user_regs, 0, sizeof(v->arch.user_regs));
    v->arch.user_regs.eflags = X86_EFLAGS_MBS;
    v->arch.user_regs.edx = 0x00000f00;
    v->arch.user_regs.eip = ip;
    memset(&v->arch.debugreg, 0, sizeof(v->arch.debugreg));

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

    v->arch.hvm_vcpu.msr_tsc_adjust = 0;

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
        int rc;

        vlapic_reset(vcpu_vlapic(v));
        rc = vcpu_reset(v);
        ASSERT(!rc);
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
    {
        struct vcpu *v;

        for_each_vcpu( d, v )
            hvm_set_guest_tsc(v, 0);
        domain_unpause(d);
    }
}

static int hvmop_set_isa_irq_level(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_isa_irq_level_t) uop)
{
    struct xen_hvm_set_isa_irq_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( op.isa_irq > 15 )
        return -EINVAL;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_isa_irq_level(XSM_DM_PRIV, d);
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
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_pci_link_route_t) uop)
{
    struct xen_hvm_set_pci_link_route op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.link > 3) || (op.isa_irq > 15) )
        return -EINVAL;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_pci_link_route(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = 0;
    hvm_set_pci_link_route(d, op.link, op.isa_irq);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_inject_msi(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_inject_msi_t) uop)
{
    struct xen_hvm_inject_msi op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_inject_msi(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    hvm_inject_msi(d, op.addr, op.data);

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
    flush_tlb_mask(d->domain_dirty_cpumask);

    /* Done. */
    for_each_vcpu ( d, v )
        if ( v != current )
            vcpu_unpause(v);

    return 0;
}

static int hvm_replace_event_channel(struct vcpu *v, domid_t remote_domid,
                                     int *p_port)
{
    int old_port, new_port;

    new_port = alloc_unbound_xen_event_channel(v, remote_domid, NULL);
    if ( new_port < 0 )
        return new_port;

    /* xchg() ensures that only we call free_xen_event_channel(). */
    old_port = xchg(p_port, new_port);
    free_xen_event_channel(v, old_port);
    return 0;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) arg)

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

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = -EINVAL;
        if ( !has_hvm_container_domain(d) )
            goto param_fail;

        if ( is_pvh_domain(d)
             && (a.index != HVM_PARAM_CALLBACK_IRQ) )
            goto param_fail;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
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
                if ( d->vcpu[0] )
                    rc = hvm_replace_event_channel(d->vcpu[0], a.value,
                             (int *)&d->vcpu[0]->domain->arch.hvm_domain.params
                                     [HVM_PARAM_BUFIOREQ_EVTCHN]);
                if ( rc )
                {
                    domain_unpause(d);
                    break;
                }
                iorp = &d->arch.hvm_domain.ioreq;
                for_each_vcpu ( d, v )
                {
                    rc = hvm_replace_event_channel(v, a.value,
                                                   &v->arch.hvm_vcpu.xen_port);
                    if ( rc )
                        break;

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
            case HVM_PARAM_ACPI_IOPORTS_LOCATION:
                rc = pmtimer_change_ioport(d, a.value);
                break;
            case HVM_PARAM_MEMORY_EVENT_CR0:
            case HVM_PARAM_MEMORY_EVENT_CR3:
            case HVM_PARAM_MEMORY_EVENT_CR4:
                if ( d == current->domain )
                    rc = -EPERM;
                break;
            case HVM_PARAM_MEMORY_EVENT_INT3:
            case HVM_PARAM_MEMORY_EVENT_SINGLE_STEP:
            case HVM_PARAM_MEMORY_EVENT_MSR:
                if ( d == current->domain )
                {
                    rc = -EPERM;
                    break;
                }
                if ( a.value & HVMPME_onchangeonly )
                    rc = -EINVAL;
                break;
            case HVM_PARAM_NESTEDHVM:
                rc = xsm_hvm_param_nested(XSM_PRIV, d);
                if ( rc )
                    break;
                if ( a.value > 1 )
                    rc = -EINVAL;
                /* Remove the check below once we have
                 * shadow-on-shadow.
                 */
                if ( cpu_has_svm && !paging_mode_hap(d) && a.value )
                    rc = -EINVAL;
                /* Set up NHVM state for any vcpus that are already up */
                if ( a.value &&
                     !d->arch.hvm_domain.params[HVM_PARAM_NESTEDHVM] )
                    for_each_vcpu(d, v)
                        if ( rc == 0 )
                            rc = nestedhvm_vcpu_initialise(v);
                if ( !a.value || rc )
                    for_each_vcpu(d, v)
                        nestedhvm_vcpu_destroy(v);
                break;
            case HVM_PARAM_BUFIOREQ_EVTCHN:
                rc = -EINVAL;
                break;
            case HVM_PARAM_TRIPLE_FAULT_REASON:
                if ( a.value > SHUTDOWN_MAX )
                    rc = -EINVAL;
                break;
            }

            if ( rc == 0 ) 
            {
                d->arch.hvm_domain.params[a.index] = a.value;

                switch( a.index )
                {
                case HVM_PARAM_MEMORY_EVENT_INT3:
                case HVM_PARAM_MEMORY_EVENT_SINGLE_STEP:
                {
                    domain_pause(d);
                    domain_unpause(d); /* Causes guest to latch new status */
                    break;
                }
                case HVM_PARAM_MEMORY_EVENT_CR3:
                {
                    for_each_vcpu ( d, v )
                        hvm_funcs.update_guest_cr(v, 0); /* Latches new CR3 mask through CR0 code */
                    break;
                }
                }

            }

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

    case HVMOP_inject_msi:
        rc = hvmop_inject_msi(
            guest_handle_cast(arg, xen_hvm_inject_msi_t));
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

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail2;

        if ( a.nr > GB(1) >> PAGE_SHIFT )
            goto param_fail2;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
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

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail3;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
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

        while ( a.nr > 0 )
        {
            unsigned long pfn = a.first_pfn;
            struct page_info *page;

            page = get_page_from_gfn(d, pfn, NULL, P2M_UNSHARE);
            if ( page )
            {
                paging_mark_dirty(d, page_to_mfn(page));
                /* These are most probably not page tables any more */
                /* don't take a long time and don't die either */
                sh_remove_shadows(d->vcpu[0], _mfn(page_to_mfn(page)), 1, 0);
                put_page(page);
            }

            a.first_pfn++;
            a.nr--;

            /* Check for continuation if it's not the last interation */
            if ( a.nr > 0 && hypercall_preempt_check() )
            {
                if ( copy_to_guest(arg, &a, 1) )
                    rc = -EFAULT;
                else
                    rc = -EAGAIN;
                break;
            }
        }

    param_fail3:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_get_mem_type:
    {
        struct xen_hvm_get_mem_type a;
        struct domain *d;
        p2m_type_t t;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail_getmemtype;

        rc = -EINVAL;
        if ( is_hvm_domain(d) )
        {
            /* Use get_gfn query as we are interested in the current 
             * type, not in allocating or unsharing. That'll happen 
             * on access. */
            get_gfn_query_unlocked(d, a.pfn, &t);
            if ( p2m_is_mmio(t) )
                a.mem_type =  HVMMEM_mmio_dm;
            else if ( p2m_is_readonly(t) )
                a.mem_type =  HVMMEM_ram_ro;
            else if ( p2m_is_ram(t) )
                a.mem_type =  HVMMEM_ram_rw;
            else if ( p2m_is_pod(t) )
                a.mem_type =  HVMMEM_ram_rw;
            else if ( p2m_is_grant(t) )
                a.mem_type =  HVMMEM_ram_rw;
            else
                a.mem_type =  HVMMEM_mmio_dm;
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

    param_fail_getmemtype:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_set_mem_type:
    {
        struct xen_hvm_set_mem_type a;
        struct domain *d;
        
        /* Interface types to internal p2m types */
        static const p2m_type_t memtype[] = {
            [HVMMEM_ram_rw]  = p2m_ram_rw,
            [HVMMEM_ram_ro]  = p2m_ram_ro,
            [HVMMEM_mmio_dm] = p2m_mmio_dm
        };

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail4;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail4;

        rc = -EINVAL;
        if ( (a.first_pfn > domain_get_maximum_gpfn(d)) ||
             ((a.first_pfn + a.nr - 1) < a.first_pfn) ||
             ((a.first_pfn + a.nr - 1) > domain_get_maximum_gpfn(d)) )
            goto param_fail4;
            
        if ( a.hvmmem_type >= ARRAY_SIZE(memtype) )
            goto param_fail4;

        while ( a.nr )
        {
            unsigned long pfn = a.first_pfn;
            p2m_type_t t;
            p2m_type_t nt;
            mfn_t mfn;
            mfn = get_gfn_unshare(d, pfn, &t);
            if ( p2m_is_paging(t) )
            {
                put_gfn(d, pfn);
                p2m_mem_paging_populate(d, pfn);
                rc = -EINVAL;
                goto param_fail4;
            }
            if ( p2m_is_shared(t) )
            {
                put_gfn(d, pfn);
                rc = -EINVAL;
                goto param_fail4;
            } 
            if ( !p2m_is_ram(t) &&
                 (!p2m_is_hole(t) || a.hvmmem_type != HVMMEM_mmio_dm) )
            {
                put_gfn(d, pfn);
                goto param_fail4;
            }
            else
            {
                nt = p2m_change_type(d, pfn, t, memtype[a.hvmmem_type]);
                if ( nt != t )
                {
                    put_gfn(d, pfn);
                    gdprintk(XENLOG_WARNING,
                             "type of pfn %#lx changed from %d to %d while "
                             "we were trying to change it to %d\n",
                             pfn, t, nt, memtype[a.hvmmem_type]);
                    goto param_fail4;
                }
            }
            put_gfn(d, pfn);

            a.first_pfn++;
            a.nr--;

            /* Check for continuation if it's not the last interation */
            if ( a.nr > 0 && hypercall_preempt_check() )
            {
                if ( copy_to_guest(arg, &a, 1) )
                    rc = -EFAULT;
                else
                    rc = -EAGAIN;
                goto param_fail4;
            }
        }

        rc = 0;

    param_fail4:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_set_mem_access:
    {
        struct xen_hvm_set_mem_access a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail5;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail5;

        rc = -EINVAL;
        if ( (a.first_pfn != ~0ull) &&
             ((a.first_pfn > domain_get_maximum_gpfn(d)) ||
             ((a.first_pfn + a.nr - 1) < a.first_pfn) ||
             ((a.first_pfn + a.nr - 1) > domain_get_maximum_gpfn(d))) )
            goto param_fail5;
            
        rc = p2m_set_mem_access(d, a.first_pfn, a.nr, a.hvmmem_access);
        if ( rc > 0 )
        {
            a.first_pfn += a.nr - rc;
            a.nr = rc;
            if ( __copy_to_guest(arg, &a, 1) )
                rc = -EFAULT;
            else
                rc = -EAGAIN;
        }

    param_fail5:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_get_mem_access:
    {
        struct xen_hvm_get_mem_access a;
        struct domain *d;
        hvmmem_access_t access;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail6;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail6;

        rc = -EINVAL;
        if ( (a.pfn > domain_get_maximum_gpfn(d)) && a.pfn != ~0ull )
            goto param_fail6;

        rc = p2m_get_mem_access(d, a.pfn, &access);
        if ( rc != 0 )
            goto param_fail6;

        a.hvmmem_access = access;
        rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;

    param_fail6:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_pagetable_dying:
    {
        struct xen_hvm_pagetable_dying a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) || !paging_mode_shadow(d) )
            goto param_fail7;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail7;

        rc = 0;
        pagetable_dying(d, a.gpa);

    param_fail7:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_get_time: {
        xen_hvm_get_time_t gxt;

        gxt.now = NOW();
        if ( copy_to_guest(arg, &gxt, 1) )
            rc = -EFAULT;
        break;
    }

    case HVMOP_xentrace: {
        xen_hvm_xentrace_t tr;

        if ( copy_from_guest(&tr, arg, 1 ) )
            return -EFAULT;

        if ( tr.extra_bytes > sizeof(tr.extra)
             || (tr.event & ~((1u<<TRC_SUBCLS_SHIFT)-1)) )
            return -EINVAL;

        /* Cycles will be taken at the vmexit and vmenter */
        trace_var(tr.event | TRC_GUEST, 0 /*!cycles*/,
                  tr.extra_bytes, tr.extra);
        break;
    }

    case HVMOP_inject_trap: 
    {
        xen_hvm_inject_trap_t tr;
        struct domain *d;
        struct vcpu *v;

        if ( copy_from_guest(&tr, arg, 1 ) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(tr.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail8;

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail8;

        rc = -ENOENT;
        if ( tr.vcpuid >= d->max_vcpus || (v = d->vcpu[tr.vcpuid]) == NULL )
            goto param_fail8;
        
        if ( v->arch.hvm_vcpu.inject_trap.vector != -1 )
            rc = -EBUSY;
        else 
        {
            v->arch.hvm_vcpu.inject_trap.vector = tr.vector;
            v->arch.hvm_vcpu.inject_trap.type = tr.type;
            v->arch.hvm_vcpu.inject_trap.error_code = tr.error_code;
            v->arch.hvm_vcpu.inject_trap.insn_len = tr.insn_len;
            v->arch.hvm_vcpu.inject_trap.cr2 = tr.cr2;
            rc = 0;
        }

    param_fail8:
        rcu_unlock_domain(d);
        break;
    }

    default:
    {
        gdprintk(XENLOG_DEBUG, "Bad HVM op %ld.\n", op);
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

static int hvm_memory_event_traps(long p, uint32_t reason,
                                  unsigned long value, unsigned long old, 
                                  bool_t gla_valid, unsigned long gla) 
{
    struct vcpu* v = current;
    struct domain *d = v->domain;
    mem_event_request_t req = { .reason = reason };
    int rc;

    if ( !(p & HVMPME_MODE_MASK) ) 
        return 0;

    if ( (p & HVMPME_onchangeonly) && (value == old) )
        return 1;

    rc = mem_event_claim_slot(d, &d->mem_event->access);
    if ( rc == -ENOSYS )
    {
        /* If there was no ring to handle the event, then
         * simple continue executing normally. */
        return 1;
    }
    else if ( rc < 0 )
        return rc;

    if ( (p & HVMPME_MODE_MASK) == HVMPME_mode_sync ) 
    {
        req.flags |= MEM_EVENT_FLAG_VCPU_PAUSED;    
        mem_event_vcpu_pause(v);
    }

    req.gfn = value;
    req.vcpu_id = v->vcpu_id;
    if ( gla_valid ) 
    {
        req.offset = gla & ((1 << PAGE_SHIFT) - 1);
        req.gla = gla;
        req.gla_valid = 1;
    }
    
    mem_event_put_request(d, &d->mem_event->access, &req);
    
    return 1;
}

void hvm_memory_event_cr0(unsigned long value, unsigned long old) 
{
    hvm_memory_event_traps(current->domain->arch.hvm_domain
                             .params[HVM_PARAM_MEMORY_EVENT_CR0],
                           MEM_EVENT_REASON_CR0,
                           value, old, 0, 0);
}

void hvm_memory_event_cr3(unsigned long value, unsigned long old) 
{
    hvm_memory_event_traps(current->domain->arch.hvm_domain
                             .params[HVM_PARAM_MEMORY_EVENT_CR3],
                           MEM_EVENT_REASON_CR3,
                           value, old, 0, 0);
}

void hvm_memory_event_cr4(unsigned long value, unsigned long old) 
{
    hvm_memory_event_traps(current->domain->arch.hvm_domain
                             .params[HVM_PARAM_MEMORY_EVENT_CR4],
                           MEM_EVENT_REASON_CR4,
                           value, old, 0, 0);
}

void hvm_memory_event_msr(unsigned long msr, unsigned long value)
{
    hvm_memory_event_traps(current->domain->arch.hvm_domain
                             .params[HVM_PARAM_MEMORY_EVENT_MSR],
                           MEM_EVENT_REASON_MSR,
                           value, ~value, 1, msr);
}

int hvm_memory_event_int3(unsigned long gla) 
{
    uint32_t pfec = PFEC_page_present;
    unsigned long gfn;
    gfn = paging_gva_to_gfn(current, gla, &pfec);

    return hvm_memory_event_traps(current->domain->arch.hvm_domain
                                    .params[HVM_PARAM_MEMORY_EVENT_INT3],
                                  MEM_EVENT_REASON_INT3,
                                  gfn, 0, 1, gla);
}

int hvm_memory_event_single_step(unsigned long gla)
{
    uint32_t pfec = PFEC_page_present;
    unsigned long gfn;
    gfn = paging_gva_to_gfn(current, gla, &pfec);

    return hvm_memory_event_traps(current->domain->arch.hvm_domain
            .params[HVM_PARAM_MEMORY_EVENT_SINGLE_STEP],
            MEM_EVENT_REASON_SINGLESTEP,
            gfn, 0, 1, gla);
}

int nhvm_vcpu_hostrestore(struct vcpu *v, struct cpu_user_regs *regs)
{
    if (hvm_funcs.nhvm_vcpu_hostrestore)
        return hvm_funcs.nhvm_vcpu_hostrestore(v, regs);
    return -EOPNOTSUPP;
}

int nhvm_vcpu_vmexit(struct vcpu *v, struct cpu_user_regs *regs,
                     uint64_t exitcode)
{
    if (hvm_funcs.nhvm_vcpu_vmexit)
        return hvm_funcs.nhvm_vcpu_vmexit(v, regs, exitcode);
    return -EOPNOTSUPP;
}

int nhvm_vcpu_vmexit_trap(struct vcpu *v, struct hvm_trap *trap)
{
    return hvm_funcs.nhvm_vcpu_vmexit_trap(v, trap);
}

uint64_t nhvm_vcpu_guestcr3(struct vcpu *v)
{
    if (hvm_funcs.nhvm_vcpu_guestcr3)
        return hvm_funcs.nhvm_vcpu_guestcr3(v);
    return -EOPNOTSUPP;
}

uint64_t nhvm_vcpu_p2m_base(struct vcpu *v)
{
    if ( hvm_funcs.nhvm_vcpu_p2m_base )
        return hvm_funcs.nhvm_vcpu_p2m_base(v);
    return -EOPNOTSUPP;
}

uint32_t nhvm_vcpu_asid(struct vcpu *v)
{
    if (hvm_funcs.nhvm_vcpu_asid)
        return hvm_funcs.nhvm_vcpu_asid(v);
    return -EOPNOTSUPP;
}

int nhvm_vmcx_guest_intercepts_trap(struct vcpu *v, unsigned int trap, int errcode)
{
    if (hvm_funcs.nhvm_vmcx_guest_intercepts_trap)
        return hvm_funcs.nhvm_vmcx_guest_intercepts_trap(v, trap, errcode);
    return -EOPNOTSUPP;
}

bool_t nhvm_vmcx_hap_enabled(struct vcpu *v)
{
    if (hvm_funcs.nhvm_vmcx_hap_enabled)
        return hvm_funcs.nhvm_vmcx_hap_enabled(v);
    return -EOPNOTSUPP;
}

enum hvm_intblk nhvm_interrupt_blocked(struct vcpu *v)
{
    return hvm_funcs.nhvm_intr_blocked(v);
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

