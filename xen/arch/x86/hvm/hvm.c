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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

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
#include <xen/cpu.h>
#include <xen/wait.h>
#include <xen/mem_access.h>
#include <xen/rangeset.h>
#include <xen/monitor.h>
#include <xen/warning.h>
#include <xen/vpci.h>
#include <xen/nospec.h>
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
#include <asm/mce.h>
#include <asm/monitor.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/hvm/trace.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/monitor.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/vm_event.h>
#include <asm/altp2m.h>
#include <asm/mtrr.h>
#include <asm/apic.h>
#include <asm/vm_event.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/version.h>
#include <public/memory.h>
#include <public/vm_event.h>
#include <public/arch-x86/cpuid.h>
#include <asm/cpuid.h>

#include <compat/hvm/hvm_op.h>

bool_t __read_mostly hvm_enabled;

#ifdef DBG_LEVEL_0
unsigned int opt_hvm_debug_level __read_mostly;
integer_param("hvm_debug", opt_hvm_debug_level);
#endif

struct hvm_function_table hvm_funcs __read_mostly;

/*
 * The I/O permission bitmap is globally shared by all HVM guests except
 * the hardware domain which needs a more permissive one.
 */
#define HVM_IOBITMAP_SIZE (3 * PAGE_SIZE)
unsigned long __section(".bss.page_aligned") __aligned(PAGE_SIZE)
    hvm_io_bitmap[HVM_IOBITMAP_SIZE / BYTES_PER_LONG];

/* Xen command-line option to enable HAP */
static bool_t __initdata opt_hap_enabled = 1;
boolean_param("hap", opt_hap_enabled);

#ifndef opt_hvm_fep
/* Permit use of the Forced Emulation Prefix in HVM guests */
bool_t __read_mostly opt_hvm_fep;
boolean_param("hvm_fep", opt_hvm_fep);
#endif
static const char __initconst warning_hvm_fep[] =
    "WARNING: HVM FORCED EMULATION PREFIX IS AVAILABLE\n"
    "This option is *ONLY* intended to aid testing of Xen.\n"
    "It has implications on the security of the system.\n"
    "Please *DO NOT* use this in production.\n";

/* Xen command-line option to enable altp2m */
static bool_t __initdata opt_altp2m_enabled = 0;
boolean_param("altp2m", opt_altp2m_enabled);

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
        {
            printk(", 2MB%s", opt_hap_2mb ? "" : " [disabled]");
            if ( !opt_hap_2mb )
                hvm_funcs.hap_capabilities &= ~HVM_HAP_SUPERPAGE_2MB;
        }
        if ( fns->hap_capabilities & HVM_HAP_SUPERPAGE_1GB )
        {
            printk(", 1GB%s", opt_hap_1gb ? "" : " [disabled]");
            if ( !opt_hap_1gb )
                hvm_funcs.hap_capabilities &= ~HVM_HAP_SUPERPAGE_1GB;
        }
        printk("\n");
    }

    if ( !opt_altp2m_enabled )
        hvm_funcs.altp2m_supported = 0;

    if ( opt_hvm_fep )
        warning_add(warning_hvm_fep);

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
    const unsigned int contributory_exceptions =
        (1 << TRAP_divide_error) |
        (1 << TRAP_invalid_tss) |
        (1 << TRAP_no_segment) |
        (1 << TRAP_stack_error) |
        (1 << TRAP_gp_fault);
    const unsigned int page_faults =
        (1 << TRAP_page_fault) |
        (1 << TRAP_virtualisation);

    /* Exception during double-fault delivery always causes a triple fault. */
    if ( vec1 == TRAP_double_fault )
    {
        hvm_triple_fault();
        return TRAP_double_fault; /* dummy return */
    }

    /* Exception during page-fault delivery always causes a double fault. */
    if ( (1u << vec1) & page_faults )
        return TRAP_double_fault;

    /* Discard the first exception if it's benign or if we now have a #PF. */
    if ( !((1u << vec1) & contributory_exceptions) ||
         ((1u << vec2) & page_faults) )
        return vec2;

    /* Cannot combine the exceptions: double fault. */
    return TRAP_double_fault;
}

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        alternative_vcall(hvm_funcs.set_rdtsc_exiting, v, enable);
}

void hvm_get_guest_pat(struct vcpu *v, u64 *guest_pat)
{
    if ( !alternative_call(hvm_funcs.get_guest_pat, v, guest_pat) )
        *guest_pat = v->arch.hvm.pat_cr;
}

int hvm_set_guest_pat(struct vcpu *v, u64 guest_pat)
{
    int i;
    uint8_t *value = (uint8_t *)&guest_pat;

    for ( i = 0; i < 8; i++ )
        switch ( value[i] )
        {
        case PAT_TYPE_UC_MINUS:
        case PAT_TYPE_UNCACHABLE:
        case PAT_TYPE_WRBACK:
        case PAT_TYPE_WRCOMB:
        case PAT_TYPE_WRPROT:
        case PAT_TYPE_WRTHROUGH:
            break;
        default:
            HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid guest PAT: %"PRIx64"\n",
                        guest_pat); 
            return 0;
        }

    if ( !alternative_call(hvm_funcs.set_guest_pat, v, guest_pat) )
        v->arch.hvm.pat_cr = guest_pat;

    return 1;
}

bool hvm_set_guest_bndcfgs(struct vcpu *v, u64 val)
{
    if ( !hvm_funcs.set_guest_bndcfgs ||
         !is_canonical_address(val) ||
         (val & IA32_BNDCFGS_RESERVED) )
        return false;

    /*
     * While MPX instructions are supposed to be gated on XCR0.BND*, let's
     * nevertheless force the relevant XCR0 bits on when the feature is being
     * enabled in BNDCFGS.
     */
    if ( (val & IA32_BNDCFGS_ENABLE) &&
         !(v->arch.xcr0_accum & (X86_XCR0_BNDREGS | X86_XCR0_BNDCSR)) )
    {
        uint64_t xcr0 = get_xcr0();
        int rc;

        if ( v != current )
            return false;

        rc = handle_xsetbv(XCR_XFEATURE_ENABLED_MASK,
                           xcr0 | X86_XCR0_BNDREGS | X86_XCR0_BNDCSR);

        if ( rc )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Failed to force XCR0.BND*: %d", rc);
            return false;
        }

        if ( handle_xsetbv(XCR_XFEATURE_ENABLED_MASK, xcr0) )
            /* nothing, best effort only */;
    }

    return alternative_call(hvm_funcs.set_guest_bndcfgs, v, val);
}

/*
 * Get the ratio to scale host TSC frequency to gtsc_khz. zero will be
 * returned if TSC scaling is unavailable or ratio cannot be handled
 * by host CPU. Otherwise, a non-zero ratio will be returned.
 */
u64 hvm_get_tsc_scaling_ratio(u32 gtsc_khz)
{
    u8 ratio_frac_bits = hvm_funcs.tsc_scaling.ratio_frac_bits;
    u64 max_ratio = hvm_funcs.tsc_scaling.max_ratio;
    u64 ratio, dummy;

    if ( !hvm_tsc_scaling_supported )
        return 0;

    /*
     * Return early if the quotient is too large to fit in the integral
     * part of TSC scaling ratio. This also avoids #DE from the following
     * divq when the quotient can not fit in a 64-bit integer.
     */
    if ( gtsc_khz / cpu_khz > (max_ratio >> ratio_frac_bits) )
        return 0;

    /* ratio = (gtsc_khz << hvm_funcs.tsc_scaling.ratio_frac_bits) / cpu_khz */
    asm ( "shldq %[frac],%[gkhz],%[zero] ; "
          "shlq  %[frac],%[gkhz]         ; "
          "divq  %[hkhz]                   "
          : "=d" (dummy), "=a" (ratio)
          : [frac] "c" (ratio_frac_bits),
            [gkhz] "a" ((u64) gtsc_khz),
            [zero] "d" (0ULL),
            [hkhz] "rm" ((u64) cpu_khz) );

    return ratio > max_ratio ? 0 : ratio;
}

u64 hvm_scale_tsc(const struct domain *d, u64 tsc)
{
    u64 ratio = d->arch.hvm.tsc_scaling_ratio;
    u64 dummy;

    if ( ratio == hvm_default_tsc_scaling_ratio )
        return tsc;

    /* tsc = (tsc * ratio) >> hvm_funcs.tsc_scaling.ratio_frac_bits */
    asm ( "mulq %[ratio]; shrdq %[frac],%%rdx,%[tsc]"
          : [tsc] "+a" (tsc), "=&d" (dummy)
          : [frac] "c" (hvm_funcs.tsc_scaling.ratio_frac_bits),
            [ratio] "rm" (ratio) );

    return tsc;
}

static void hvm_set_guest_tsc_fixed(struct vcpu *v, u64 guest_tsc, u64 at_tsc)
{
    uint64_t tsc;
    uint64_t delta_tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time_fixed(v, at_tsc);
        tsc = gtime_to_gtsc(v->domain, tsc);
    }
    else
    {
        tsc = at_tsc ?: rdtsc();
        if ( hvm_tsc_scaling_supported )
            tsc = hvm_scale_tsc(v->domain, tsc);
    }

    delta_tsc = guest_tsc - tsc;
    v->arch.hvm.cache_tsc_offset = delta_tsc;

    hvm_set_tsc_offset(v, v->arch.hvm.cache_tsc_offset, at_tsc);
}

#define hvm_set_guest_tsc(v, t) hvm_set_guest_tsc_fixed(v, t, 0)

static void hvm_set_guest_tsc_msr(struct vcpu *v, u64 guest_tsc)
{
    uint64_t tsc_offset = v->arch.hvm.cache_tsc_offset;

    hvm_set_guest_tsc(v, guest_tsc);
    v->arch.hvm.msr_tsc_adjust += v->arch.hvm.cache_tsc_offset - tsc_offset;
}

static void hvm_set_guest_tsc_adjust(struct vcpu *v, u64 tsc_adjust)
{
    v->arch.hvm.cache_tsc_offset += tsc_adjust - v->arch.hvm.msr_tsc_adjust;
    hvm_set_tsc_offset(v, v->arch.hvm.cache_tsc_offset, 0);
    v->arch.hvm.msr_tsc_adjust = tsc_adjust;
}

u64 hvm_get_guest_tsc_fixed(struct vcpu *v, uint64_t at_tsc)
{
    uint64_t tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time_fixed(v, at_tsc);
        tsc = gtime_to_gtsc(v->domain, tsc);
    }
    else
    {
        tsc = at_tsc ?: rdtsc();
        if ( hvm_tsc_scaling_supported )
            tsc = hvm_scale_tsc(v->domain, tsc);
    }

    return tsc + v->arch.hvm.cache_tsc_offset;
}

void hvm_migrate_timers(struct vcpu *v)
{
    rtc_migrate_timers(v);
    pt_migrate(v);
}

void hvm_migrate_pirq(struct hvm_pirq_dpci *pirq_dpci, const struct vcpu *v)
{
    ASSERT(iommu_enabled &&
           (is_hardware_domain(v->domain) || hvm_domain_irq(v->domain)->dpci));

    if ( (pirq_dpci->flags & HVM_IRQ_DPCI_MACH_MSI) &&
         /* Needn't migrate pirq if this pirq is delivered to guest directly.*/
         !pirq_dpci->gmsi.posted &&
         (pirq_dpci->gmsi.dest_vcpu_id == v->vcpu_id) )
    {
        struct irq_desc *desc =
            pirq_spin_lock_irq_desc(dpci_pirq(pirq_dpci), NULL);

        if ( !desc )
            return;
        ASSERT(MSI_IRQ(desc - irq_desc));
        irq_set_affinity(desc, cpumask_of(v->processor));
        spin_unlock_irq(&desc->lock);
    }
}

static int migrate_pirq(struct domain *d, struct hvm_pirq_dpci *pirq_dpci,
                        void *arg)
{
    hvm_migrate_pirq(pirq_dpci, arg);

    return 0;
}

void hvm_migrate_pirqs(struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( !iommu_enabled || !hvm_domain_irq(d)->dpci )
       return;

    spin_lock(&d->event_lock);
    pt_pirq_iterate(d, migrate_pirq, v);
    spin_unlock(&d->event_lock);
}

static bool hvm_get_pending_event(struct vcpu *v, struct x86_event *info)
{
    info->cr2 = v->arch.hvm.guest_cr[2];

    return alternative_call(hvm_funcs.get_pending_event, v, info);
}

void hvm_do_resume(struct vcpu *v)
{
    check_wakeup_from_wait();

    pt_restore_timer(v);

    if ( !handle_hvm_io_completion(v) )
        return;

    if ( unlikely(v->arch.vm_event) )
        hvm_vm_event_do_resume(v);

    /* Inject pending hw/sw event */
    if ( v->arch.hvm.inject_event.vector >= 0 )
    {
        smp_rmb();

        if ( !hvm_event_pending(v) )
            hvm_inject_event(&v->arch.hvm.inject_event);

        v->arch.hvm.inject_event.vector = HVM_EVENT_VECTOR_UNSET;
    }

    if ( unlikely(v->arch.vm_event) && v->arch.monitor.next_interrupt_enabled )
    {
        struct x86_event info;

        if ( hvm_get_pending_event(v, &info) )
        {
            hvm_monitor_interrupt(info.vector, info.type, info.error_code,
                                  info.cr2);
            v->arch.monitor.next_interrupt_enabled = false;
        }
    }
}

static int hvm_print_line(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct domain *cd = current->domain;
    char c = *val;

    ASSERT(bytes == 1 && port == XEN_HVM_DEBUGCONS_IOPORT);

    /* Deny any input requests. */
    if ( dir != IOREQ_WRITE )
        return X86EMUL_UNHANDLEABLE;

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

int hvm_domain_initialise(struct domain *d)
{
    unsigned int nr_gsis;
    int rc;

    if ( !hvm_enabled )
    {
        gdprintk(XENLOG_WARNING, "Attempt to create a HVM guest "
                 "on a non-VT/AMDV platform.\n");
        return -EINVAL;
    }

    spin_lock_init(&d->arch.hvm.irq_lock);
    spin_lock_init(&d->arch.hvm.uc_lock);
    spin_lock_init(&d->arch.hvm.write_map.lock);
    rwlock_init(&d->arch.hvm.mmcfg_lock);
    INIT_LIST_HEAD(&d->arch.hvm.write_map.list);
    INIT_LIST_HEAD(&d->arch.hvm.g2m_ioport_list);
    INIT_LIST_HEAD(&d->arch.hvm.mmcfg_regions);
    INIT_LIST_HEAD(&d->arch.hvm.msix_tables);

    rc = create_perdomain_mapping(d, PERDOMAIN_VIRT_START, 0, NULL, NULL);
    if ( rc )
        goto fail;

    hvm_init_cacheattr_region_list(d);

    rc = paging_enable(d, PG_refcounts|PG_translate|PG_external);
    if ( rc != 0 )
        goto fail0;

    nr_gsis = is_hardware_domain(d) ? nr_irqs_gsi : NR_HVM_DOMU_IRQS;
    d->arch.hvm.pl_time = xzalloc(struct pl_time);
    d->arch.hvm.params = xzalloc_array(uint64_t, HVM_NR_PARAMS);
    d->arch.hvm.io_handler = xzalloc_array(struct hvm_io_handler,
                                           NR_IO_HANDLERS);
    d->arch.hvm.irq = xzalloc_bytes(hvm_irq_size(nr_gsis));

    rc = -ENOMEM;
    if ( !d->arch.hvm.pl_time || !d->arch.hvm.irq ||
         !d->arch.hvm.params  || !d->arch.hvm.io_handler )
        goto fail1;

    /* Set the number of GSIs */
    hvm_domain_irq(d)->nr_gsis = nr_gsis;

    BUILD_BUG_ON(NR_HVM_DOMU_IRQS < NR_ISAIRQS);
    ASSERT(hvm_domain_irq(d)->nr_gsis >= NR_ISAIRQS);

    /* need link to containing domain */
    d->arch.hvm.pl_time->domain = d;

    /* Set the default IO Bitmap. */
    if ( is_hardware_domain(d) )
    {
        d->arch.hvm.io_bitmap = _xmalloc(HVM_IOBITMAP_SIZE, PAGE_SIZE);
        if ( d->arch.hvm.io_bitmap == NULL )
        {
            rc = -ENOMEM;
            goto fail1;
        }
        memset(d->arch.hvm.io_bitmap, ~0, HVM_IOBITMAP_SIZE);
    }
    else
        d->arch.hvm.io_bitmap = hvm_io_bitmap;

    register_g2m_portio_handler(d);
    register_vpci_portio_handler(d);

    hvm_ioreq_init(d);

    hvm_init_guest_time(d);

    d->arch.hvm.params[HVM_PARAM_TRIPLE_FAULT_REASON] = SHUTDOWN_reboot;

    vpic_init(d);

    rc = vioapic_init(d);
    if ( rc != 0 )
        goto fail1;

    stdvga_init(d);

    rtc_init(d);

    register_portio_handler(d, XEN_HVM_DEBUGCONS_IOPORT, 1, hvm_print_line);

    if ( hvm_tsc_scaling_supported )
        d->arch.hvm.tsc_scaling_ratio = hvm_default_tsc_scaling_ratio;

    rc = viridian_domain_init(d);
    if ( rc )
        goto fail2;

    rc = hvm_funcs.domain_initialise(d);
    if ( rc != 0 )
        goto fail2;

    return 0;

 fail2:
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);
 fail1:
    if ( is_hardware_domain(d) )
        xfree(d->arch.hvm.io_bitmap);
    xfree(d->arch.hvm.io_handler);
    xfree(d->arch.hvm.params);
    xfree(d->arch.hvm.pl_time);
    xfree(d->arch.hvm.irq);
 fail0:
    hvm_destroy_cacheattr_region_list(d);
    destroy_perdomain_mapping(d, PERDOMAIN_VIRT_START, 0);
 fail:
    viridian_domain_deinit(d);
    return rc;
}

void hvm_domain_relinquish_resources(struct domain *d)
{
    if ( hvm_funcs.nhvm_domain_relinquish_resources )
        hvm_funcs.nhvm_domain_relinquish_resources(d);

    viridian_domain_deinit(d);

    hvm_destroy_all_ioreq_servers(d);

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
    struct list_head *ioport_list, *tmp;
    struct g2m_ioport *ioport;

    XFREE(d->arch.hvm.io_handler);
    XFREE(d->arch.hvm.params);

    hvm_destroy_cacheattr_region_list(d);

    hvm_funcs.domain_destroy(d);
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);

    XFREE(d->arch.hvm.pl_time);
    XFREE(d->arch.hvm.irq);

    list_for_each_safe ( ioport_list, tmp, &d->arch.hvm.g2m_ioport_list )
    {
        ioport = list_entry(ioport_list, struct g2m_ioport, list);
        list_del(&ioport->list);
        xfree(ioport);
    }

    destroy_vpci_mmcfg(d);
}

static int hvm_save_tsc_adjust(struct vcpu *v, hvm_domain_context_t *h)
{
    struct hvm_tsc_adjust ctxt = {
        .tsc_adjust = v->arch.hvm.msr_tsc_adjust,
    };

    return hvm_save_entry(TSC_ADJUST, v->vcpu_id, h, &ctxt);
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

    v->arch.hvm.msr_tsc_adjust = ctxt.tsc_adjust;
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(TSC_ADJUST, hvm_save_tsc_adjust,
                          hvm_load_tsc_adjust, 1, HVMSR_PER_VCPU);

static int hvm_save_cpu_ctxt(struct vcpu *v, hvm_domain_context_t *h)
{
    struct segment_register seg;
    struct hvm_hw_cpu ctxt = {
        .tsc = hvm_get_guest_tsc_fixed(v, v->domain->arch.hvm.sync_tsc),
        .msr_tsc_aux = v->arch.msrs->tsc_aux,
        .rax = v->arch.user_regs.rax,
        .rbx = v->arch.user_regs.rbx,
        .rcx = v->arch.user_regs.rcx,
        .rdx = v->arch.user_regs.rdx,
        .rbp = v->arch.user_regs.rbp,
        .rsi = v->arch.user_regs.rsi,
        .rdi = v->arch.user_regs.rdi,
        .rsp = v->arch.user_regs.rsp,
        .rip = v->arch.user_regs.rip,
        .rflags = v->arch.user_regs.rflags,
        .r8  = v->arch.user_regs.r8,
        .r9  = v->arch.user_regs.r9,
        .r10 = v->arch.user_regs.r10,
        .r11 = v->arch.user_regs.r11,
        .r12 = v->arch.user_regs.r12,
        .r13 = v->arch.user_regs.r13,
        .r14 = v->arch.user_regs.r14,
        .r15 = v->arch.user_regs.r15,
        .cr0 = v->arch.hvm.guest_cr[0],
        .cr2 = v->arch.hvm.guest_cr[2],
        .cr3 = v->arch.hvm.guest_cr[3],
        .cr4 = v->arch.hvm.guest_cr[4],
        .dr0 = v->arch.dr[0],
        .dr1 = v->arch.dr[1],
        .dr2 = v->arch.dr[2],
        .dr3 = v->arch.dr[3],
        .dr6 = v->arch.dr6,
        .dr7 = v->arch.dr7,
        .msr_efer = v->arch.hvm.guest_efer,
    };

    /*
     * We don't need to save state for a vcpu that is down; the restore
     * code will leave it down if there is nothing saved.
     */
    if ( v->pause_flags & VPF_down )
        return 0;

    /* Architecture-specific vmcs/vmcb bits */
    hvm_funcs.save_cpu_ctxt(v, &ctxt);

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
    ctxt.cs_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_ds, &seg);
    ctxt.ds_sel = seg.sel;
    ctxt.ds_limit = seg.limit;
    ctxt.ds_base = seg.base;
    ctxt.ds_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_es, &seg);
    ctxt.es_sel = seg.sel;
    ctxt.es_limit = seg.limit;
    ctxt.es_base = seg.base;
    ctxt.es_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_ss, &seg);
    ctxt.ss_sel = seg.sel;
    ctxt.ss_limit = seg.limit;
    ctxt.ss_base = seg.base;
    ctxt.ss_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_fs, &seg);
    ctxt.fs_sel = seg.sel;
    ctxt.fs_limit = seg.limit;
    ctxt.fs_base = seg.base;
    ctxt.fs_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_gs, &seg);
    ctxt.gs_sel = seg.sel;
    ctxt.gs_limit = seg.limit;
    ctxt.gs_base = seg.base;
    ctxt.gs_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_tr, &seg);
    ctxt.tr_sel = seg.sel;
    ctxt.tr_limit = seg.limit;
    ctxt.tr_base = seg.base;
    ctxt.tr_arbytes = seg.attr;

    hvm_get_segment_register(v, x86_seg_ldtr, &seg);
    ctxt.ldtr_sel = seg.sel;
    ctxt.ldtr_limit = seg.limit;
    ctxt.ldtr_base = seg.base;
    ctxt.ldtr_arbytes = seg.attr;

    if ( v->fpu_initialised )
    {
        memcpy(ctxt.fpu_regs, v->arch.fpu_ctxt, sizeof(ctxt.fpu_regs));
        ctxt.flags = XEN_X86_FPU_INITIALISED;
    }

    return hvm_save_entry(CPU, v->vcpu_id, h, &ctxt);
}

/* Return a string indicating the error, or NULL for valid. */
const char *hvm_efer_valid(const struct vcpu *v, uint64_t value,
                           signed int cr0_pg)
{
    const struct domain *d = v->domain;
    const struct cpuid_policy *p = d->arch.cpuid;

    if ( value & ~EFER_KNOWN_MASK )
        return "Unknown bits set";

    if ( (value & EFER_SCE) && !p->extd.syscall )
        return "SCE without feature";

    if ( (value & (EFER_LME | EFER_LMA)) && !p->extd.lm )
        return "LME/LMA without feature";

    if ( (value & EFER_LMA) && (!(value & EFER_LME) || !cr0_pg) )
        return "LMA/LME/CR0.PG inconsistency";

    if ( (value & EFER_NX) && !p->extd.nx )
        return "NX without feature";

    if ( (value & EFER_SVME) && (!p->extd.svm || !nestedhvm_enabled(d)) )
        return "SVME without nested virt";

    if ( (value & EFER_FFXSE) && !p->extd.ffxsr )
        return "FFXSE without feature";

    return NULL;
}

/* These reserved bits in lower 32 remain 0 after any load of CR0 */
#define HVM_CR0_GUEST_RESERVED_BITS             \
    (~((unsigned long)                          \
       (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM |  \
        X86_CR0_TS | X86_CR0_ET | X86_CR0_NE |  \
        X86_CR0_WP | X86_CR0_AM | X86_CR0_NW |  \
        X86_CR0_CD | X86_CR0_PG)))

/* These bits in CR4 can be set by the guest. */
unsigned long hvm_cr4_guest_valid_bits(const struct domain *d, bool restore)
{
    const struct cpuid_policy *p = d->arch.cpuid;
    bool mce, vmxe;

    /* Logic broken out simply to aid readability below. */
    mce  = p->basic.mce || p->basic.mca;
    vmxe = p->basic.vmx && (restore || nestedhvm_enabled(d));

    return ((p->basic.vme     ? X86_CR4_VME | X86_CR4_PVI : 0) |
            (p->basic.tsc     ? X86_CR4_TSD               : 0) |
            (p->basic.de      ? X86_CR4_DE                : 0) |
            (p->basic.pse     ? X86_CR4_PSE               : 0) |
            (p->basic.pae     ? X86_CR4_PAE               : 0) |
            (mce              ? X86_CR4_MCE               : 0) |
            (p->basic.pge     ? X86_CR4_PGE               : 0) |
                                X86_CR4_PCE                    |
            (p->basic.fxsr    ? X86_CR4_OSFXSR            : 0) |
            (p->basic.sse     ? X86_CR4_OSXMMEXCPT        : 0) |
            (p->feat.umip     ? X86_CR4_UMIP              : 0) |
            (vmxe             ? X86_CR4_VMXE              : 0) |
            (p->feat.fsgsbase ? X86_CR4_FSGSBASE          : 0) |
            (p->basic.pcid    ? X86_CR4_PCIDE             : 0) |
            (p->basic.xsave   ? X86_CR4_OSXSAVE           : 0) |
            (p->feat.smep     ? X86_CR4_SMEP              : 0) |
            (p->feat.smap     ? X86_CR4_SMAP              : 0) |
            (p->feat.pku      ? X86_CR4_PKE               : 0));
}

static int hvm_load_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;
    const char *errstr;

    /* Which vcpu is this? */
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%u has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry_zeroextend(CPU, h, &ctxt) != 0 )
        return -EINVAL;

    if ( ctxt.pad0 != 0 )
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

    if ( ctxt.cr4 & ~hvm_cr4_guest_valid_bits(d, true) )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad CR4 %#" PRIx64 "\n",
               d->domain_id, ctxt.cr4);
        return -EINVAL;
    }

    errstr = hvm_efer_valid(v, ctxt.msr_efer, MASK_EXTR(ctxt.cr0, X86_CR0_PG));
    if ( errstr )
    {
        printk(XENLOG_G_ERR "%pv: HVM restore: bad EFER %#" PRIx64 " - %s\n",
               v, ctxt.msr_efer, errstr);
        return -EINVAL;
    }

    if ( (ctxt.flags & ~XEN_X86_FPU_INITIALISED) != 0 )
    {
        gprintk(XENLOG_ERR, "bad flags value in CPU context: %#x\n",
                ctxt.flags);
        return -EINVAL;
    }

    if ( ctxt.msr_tsc_aux != (uint32_t)ctxt.msr_tsc_aux )
    {
        printk(XENLOG_G_ERR "%pv: HVM restore: bad MSR_TSC_AUX %#"PRIx64"\n",
               v, ctxt.msr_tsc_aux);
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

    v->arch.hvm.guest_cr[2] = ctxt.cr2;
    hvm_update_guest_cr(v, 2);

    if ( hvm_funcs.tsc_scaling.setup )
        hvm_funcs.tsc_scaling.setup(v);

    v->arch.msrs->tsc_aux = ctxt.msr_tsc_aux;

    hvm_set_guest_tsc_fixed(v, ctxt.tsc, d->arch.hvm.sync_tsc);

    seg.limit = ctxt.idtr_limit;
    seg.base = ctxt.idtr_base;
    hvm_set_segment_register(v, x86_seg_idtr, &seg);

    seg.limit = ctxt.gdtr_limit;
    seg.base = ctxt.gdtr_base;
    hvm_set_segment_register(v, x86_seg_gdtr, &seg);

    seg.sel = ctxt.cs_sel;
    seg.limit = ctxt.cs_limit;
    seg.base = ctxt.cs_base;
    seg.attr = ctxt.cs_arbytes;
    hvm_set_segment_register(v, x86_seg_cs, &seg);

    seg.sel = ctxt.ds_sel;
    seg.limit = ctxt.ds_limit;
    seg.base = ctxt.ds_base;
    seg.attr = ctxt.ds_arbytes;
    hvm_set_segment_register(v, x86_seg_ds, &seg);

    seg.sel = ctxt.es_sel;
    seg.limit = ctxt.es_limit;
    seg.base = ctxt.es_base;
    seg.attr = ctxt.es_arbytes;
    hvm_set_segment_register(v, x86_seg_es, &seg);

    seg.sel = ctxt.ss_sel;
    seg.limit = ctxt.ss_limit;
    seg.base = ctxt.ss_base;
    seg.attr = ctxt.ss_arbytes;
    hvm_set_segment_register(v, x86_seg_ss, &seg);

    seg.sel = ctxt.fs_sel;
    seg.limit = ctxt.fs_limit;
    seg.base = ctxt.fs_base;
    seg.attr = ctxt.fs_arbytes;
    hvm_set_segment_register(v, x86_seg_fs, &seg);

    seg.sel = ctxt.gs_sel;
    seg.limit = ctxt.gs_limit;
    seg.base = ctxt.gs_base;
    seg.attr = ctxt.gs_arbytes;
    hvm_set_segment_register(v, x86_seg_gs, &seg);

    seg.sel = ctxt.tr_sel;
    seg.limit = ctxt.tr_limit;
    seg.base = ctxt.tr_base;
    seg.attr = ctxt.tr_arbytes;
    hvm_set_segment_register(v, x86_seg_tr, &seg);

    seg.sel = ctxt.ldtr_sel;
    seg.limit = ctxt.ldtr_limit;
    seg.base = ctxt.ldtr_base;
    seg.attr = ctxt.ldtr_arbytes;
    hvm_set_segment_register(v, x86_seg_ldtr, &seg);

    /* Cover xsave-absent save file restoration on xsave-capable host. */
    vcpu_setup_fpu(v, xsave_enabled(v) ? NULL : v->arch.xsave_area,
                   ctxt.flags & XEN_X86_FPU_INITIALISED ? ctxt.fpu_regs : NULL,
                   FCW_RESET);

    v->arch.user_regs.rax = ctxt.rax;
    v->arch.user_regs.rbx = ctxt.rbx;
    v->arch.user_regs.rcx = ctxt.rcx;
    v->arch.user_regs.rdx = ctxt.rdx;
    v->arch.user_regs.rbp = ctxt.rbp;
    v->arch.user_regs.rsi = ctxt.rsi;
    v->arch.user_regs.rdi = ctxt.rdi;
    v->arch.user_regs.rsp = ctxt.rsp;
    v->arch.user_regs.rip = ctxt.rip;
    v->arch.user_regs.rflags = ctxt.rflags | X86_EFLAGS_MBS;
    v->arch.user_regs.r8  = ctxt.r8;
    v->arch.user_regs.r9  = ctxt.r9;
    v->arch.user_regs.r10 = ctxt.r10;
    v->arch.user_regs.r11 = ctxt.r11;
    v->arch.user_regs.r12 = ctxt.r12;
    v->arch.user_regs.r13 = ctxt.r13;
    v->arch.user_regs.r14 = ctxt.r14;
    v->arch.user_regs.r15 = ctxt.r15;
    v->arch.dr[0] = ctxt.dr0;
    v->arch.dr[1] = ctxt.dr1;
    v->arch.dr[2] = ctxt.dr2;
    v->arch.dr[3] = ctxt.dr3;
    v->arch.dr6   = ctxt.dr6;
    v->arch.dr7   = ctxt.dr7;

    v->arch.vgc_flags = VGCF_online;

    /* Auxiliary processors should be woken immediately. */
    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);
    vcpu_wake(v);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(CPU, hvm_save_cpu_ctxt, hvm_load_cpu_ctxt, 1,
                          HVMSR_PER_VCPU);

#define HVM_CPU_XSAVE_SIZE(xcr0) (offsetof(struct hvm_hw_cpu_xsave, \
                                           save_area) + \
                                  xstate_ctxt_size(xcr0))

static int hvm_save_cpu_xsave_states(struct vcpu *v, hvm_domain_context_t *h)
{
    struct hvm_hw_cpu_xsave *ctxt;
    unsigned int size = HVM_CPU_XSAVE_SIZE(v->arch.xcr0_accum);
    int err;

    if ( !cpu_has_xsave || !xsave_enabled(v) )
        return 0;   /* do nothing */

    err = _hvm_init_entry(h, CPU_XSAVE_CODE, v->vcpu_id, size);
    if ( err )
        return err;

    ctxt = (struct hvm_hw_cpu_xsave *)&h->data[h->cur];
    h->cur += size;
    ctxt->xfeature_mask = xfeature_mask;
    ctxt->xcr0 = v->arch.xcr0;
    ctxt->xcr0_accum = v->arch.xcr0_accum;

    expand_xsave_states(v, &ctxt->save_area,
                        size - offsetof(typeof(*ctxt), save_area));

    return 0;
}

/*
 * Structure layout conformity checks, documenting correctness of the cast in
 * the invocation of validate_xstate() below.
 * Leverage CONFIG_COMPAT machinery to perform this.
 */
#define xen_xsave_hdr xsave_hdr
#define compat_xsave_hdr hvm_hw_cpu_xsave_hdr
CHECK_FIELD_(struct, xsave_hdr, xstate_bv);
CHECK_FIELD_(struct, xsave_hdr, xcomp_bv);
CHECK_FIELD_(struct, xsave_hdr, reserved);
#undef compat_xsave_hdr
#undef xen_xsave_hdr

static int hvm_load_cpu_xsave_states(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid, size;
    int err;
    struct vcpu *v;
    struct hvm_hw_cpu_xsave *ctxt;
    const struct hvm_save_descriptor *desc;
    unsigned int i, desc_start, desc_length;

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
    h->cur += sizeof (*desc);
    desc_start = h->cur;

    ctxt = (struct hvm_hw_cpu_xsave *)&h->data[h->cur];
    h->cur += desc->length;

    err = validate_xstate(d, ctxt->xcr0, ctxt->xcr0_accum,
                          (const void *)&ctxt->save_area.xsave_hdr);
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
    desc_length = desc->length;
    if ( desc_length > size )
    {
        /*
         * Xen 4.3.0, 4.2.3 and older used to send longer-than-needed
         * xsave regions.  Permit loading the record if the extra data
         * is all zero.
         */
        for ( i = size; i < desc->length; i++ )
        {
            if ( h->data[desc_start + i] )
            {
                printk(XENLOG_G_WARNING
                       "HVM%d.%u restore mismatch: xsave length %#x > %#x (non-zero data at %#x)\n",
                       d->domain_id, vcpuid, desc->length, size, i);
                return -EOPNOTSUPP;
            }
        }
        printk(XENLOG_G_WARNING
               "HVM%d.%u restore mismatch: xsave length %#x > %#x\n",
               d->domain_id, vcpuid, desc->length, size);
        /* Rewind desc_length to ignore the extraneous zeros. */
        desc_length = size;
    }

    if ( xsave_area_compressed((const void *)&ctxt->save_area) )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%u restore: compressed xsave state not supported\n",
               d->domain_id, vcpuid);
        return -EOPNOTSUPP;
    }
    else if ( desc_length != size )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%u restore mismatch: xsave length %#x != %#x\n",
               d->domain_id, vcpuid, desc_length, size);
        return -EINVAL;
    }
    /* Checking finished */

    v->arch.xcr0 = ctxt->xcr0;
    v->arch.xcr0_accum = ctxt->xcr0_accum;
    v->arch.nonlazy_xstate_used = ctxt->xcr0_accum & XSTATE_NONLAZY;
    compress_xsave_states(v, &ctxt->save_area,
                          size - offsetof(struct hvm_hw_cpu_xsave, save_area));

    return 0;
}

#define HVM_CPU_MSR_SIZE(cnt) offsetof(struct hvm_msr, msr[cnt])
static const uint32_t msrs_to_send[] = {
    MSR_SPEC_CTRL,
    MSR_INTEL_MISC_FEATURES_ENABLES,
    MSR_IA32_BNDCFGS,
    MSR_IA32_XSS,
    MSR_AMD64_DR0_ADDRESS_MASK,
    MSR_AMD64_DR1_ADDRESS_MASK,
    MSR_AMD64_DR2_ADDRESS_MASK,
    MSR_AMD64_DR3_ADDRESS_MASK,
};

static int hvm_save_cpu_msrs(struct vcpu *v, hvm_domain_context_t *h)
{
    struct hvm_save_descriptor *desc = _p(&h->data[h->cur]);
    struct hvm_msr *ctxt;
    unsigned int i;
    int err;

    err = _hvm_init_entry(h, CPU_MSR_CODE, v->vcpu_id,
                             HVM_CPU_MSR_SIZE(ARRAY_SIZE(msrs_to_send)));
    if ( err )
        return err;
    ctxt = (struct hvm_msr *)&h->data[h->cur];
    ctxt->count = 0;

    for ( i = 0; i < ARRAY_SIZE(msrs_to_send); ++i )
    {
        uint64_t val;
        int rc = guest_rdmsr(v, msrs_to_send[i], &val);

        /*
         * It is the programmers responsibility to ensure that
         * msrs_to_send[] contain generally-read/write MSRs.
         * X86EMUL_EXCEPTION here implies a missing feature, and that the
         * guest doesn't have access to the MSR.
         */
        if ( rc == X86EMUL_EXCEPTION )
            continue;

        if ( rc != X86EMUL_OKAY )
        {
            ASSERT_UNREACHABLE();
            return -ENXIO;
        }

        if ( !val )
            continue; /* Skip empty MSRs. */

        ctxt->msr[ctxt->count].index = msrs_to_send[i];
        ctxt->msr[ctxt->count++].val = val;
    }

    ASSERT(ctxt->count <= ARRAY_SIZE(msrs_to_send));

    for ( i = 0; i < ctxt->count; ++i )
        ctxt->msr[i]._rsvd = 0;

    if ( ctxt->count )
    {
        /* Rewrite length to indicate how much space we actually used. */
        desc->length = HVM_CPU_MSR_SIZE(ctxt->count);
        h->cur += HVM_CPU_MSR_SIZE(ctxt->count);
    }
    else
        /* or rewind and remove the descriptor from the stream. */
        h->cur -= sizeof(struct hvm_save_descriptor);

    return 0;
}

static int hvm_load_cpu_msrs(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int i, vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    const struct hvm_save_descriptor *desc;
    struct hvm_msr *ctxt;
    int err = 0;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    /* Customized checking for entry since our entry is of variable length */
    desc = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read MSR descriptor\n",
               d->domain_id, vcpuid);
        return -ENODATA;
    }
    if ( desc->length + sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read %u MSR bytes\n",
               d->domain_id, vcpuid, desc->length);
        return -ENODATA;
    }
    if ( desc->length < HVM_CPU_MSR_SIZE(1) )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: MSR length %u < %zu\n",
               d->domain_id, vcpuid, desc->length, HVM_CPU_MSR_SIZE(1));
        return -EINVAL;
    }

    h->cur += sizeof(*desc);
    ctxt = (struct hvm_msr *)&h->data[h->cur];
    h->cur += desc->length;

    if ( desc->length != HVM_CPU_MSR_SIZE(ctxt->count) )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: MSR length %u != %zu\n",
               d->domain_id, vcpuid, desc->length,
               HVM_CPU_MSR_SIZE(ctxt->count));
        return -EOPNOTSUPP;
    }

    for ( i = 0; i < ctxt->count; ++i )
        if ( ctxt->msr[i]._rsvd )
            return -EOPNOTSUPP;
    /* Checking finished */

    for ( i = 0; !err && i < ctxt->count; ++i )
    {
        switch ( ctxt->msr[i].index )
        {
            int rc;

        case MSR_SPEC_CTRL:
        case MSR_INTEL_MISC_FEATURES_ENABLES:
        case MSR_IA32_BNDCFGS:
        case MSR_IA32_XSS:
        case MSR_AMD64_DR0_ADDRESS_MASK:
        case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
            rc = guest_wrmsr(v, ctxt->msr[i].index, ctxt->msr[i].val);

            if ( rc != X86EMUL_OKAY )
                err = -ENXIO;
            break;

        default:
            if ( !ctxt->msr[i]._rsvd )
                err = -ENXIO;
            break;
        }
    }

    return err;
}

/* We need variable length data chunks for XSAVE area and MSRs, hence
 * a custom declaration rather than HVM_REGISTER_SAVE_RESTORE.
 */
static int __init hvm_register_CPU_save_and_restore(void)
{
    hvm_register_savevm(CPU_XSAVE_CODE,
                        "CPU_XSAVE",
                        hvm_save_cpu_xsave_states,
                        hvm_load_cpu_xsave_states,
                        HVM_CPU_XSAVE_SIZE(xfeature_mask) +
                            sizeof(struct hvm_save_descriptor),
                        HVMSR_PER_VCPU);

    hvm_register_savevm(CPU_MSR_CODE,
                        "CPU_MSR",
                        hvm_save_cpu_msrs,
                        hvm_load_cpu_msrs,
                        HVM_CPU_MSR_SIZE(ARRAY_SIZE(msrs_to_send)) +
                            sizeof(struct hvm_save_descriptor),
                        HVMSR_PER_VCPU);

    return 0;
}
__initcall(hvm_register_CPU_save_and_restore);

int hvm_vcpu_initialise(struct vcpu *v)
{
    int rc;
    struct domain *d = v->domain;

    hvm_asid_flush_vcpu(v);

    spin_lock_init(&v->arch.hvm.tm_lock);
    INIT_LIST_HEAD(&v->arch.hvm.tm_list);

    rc = hvm_vcpu_cacheattr_init(v); /* teardown: vcpu_cacheattr_destroy */
    if ( rc != 0 )
        goto fail1;

    /* NB: vlapic_init must be called before hvm_funcs.vcpu_initialise */
    rc = vlapic_init(v);
    if ( rc != 0 ) /* teardown: vlapic_destroy */
        goto fail2;

    if ( (rc = hvm_funcs.vcpu_initialise(v)) != 0 ) /* teardown: hvm_funcs.vcpu_destroy */
        goto fail3;

    softirq_tasklet_init(
        &v->arch.hvm.assert_evtchn_irq_tasklet,
        (void(*)(unsigned long))hvm_assert_evtchn_irq,
        (unsigned long)v);

    v->arch.hvm.inject_event.vector = HVM_EVENT_VECTOR_UNSET;

    rc = setup_compat_arg_xlat(v); /* teardown: free_compat_arg_xlat() */
    if ( rc != 0 )
        goto fail4;

    vcpu_nestedhvm(v).nv_vvmcxaddr = INVALID_PADDR;

    if ( nestedhvm_enabled(d)
         && (rc = nestedhvm_vcpu_initialise(v)) < 0 ) /* teardown: nestedhvm_vcpu_destroy */
        goto fail5;

    rc = viridian_vcpu_init(v);
    if ( rc )
        goto fail5;

    rc = hvm_all_ioreq_servers_add_vcpu(d, v);
    if ( rc != 0 )
        goto fail6;

    if ( v->vcpu_id == 0 )
    {
        /* NB. All these really belong in hvm_domain_initialise(). */
        pmtimer_init(v);
        hpet_init(d);
 
        /* Init guest TSC to start from zero. */
        hvm_set_guest_tsc(v, 0);
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
    viridian_vcpu_deinit(v);
    return rc;
}

void hvm_vcpu_destroy(struct vcpu *v)
{
    viridian_vcpu_deinit(v);

    hvm_all_ioreq_servers_remove_vcpu(v->domain, v);

    if ( hvm_altp2m_supported() )
        altp2m_vcpu_destroy(v);

    nestedhvm_vcpu_destroy(v);

    free_compat_arg_xlat(v);

    tasklet_kill(&v->arch.hvm.assert_evtchn_irq_tasklet);
    hvm_funcs.vcpu_destroy(v);

    vlapic_destroy(v);

    hvm_vcpu_cacheattr_destroy(v);
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
        if ( !(v->pause_flags & VPF_down) )
            online_count++;
    domain_unlock(d);

    /* ... Shut down the domain if not. */
    if ( online_count == 0 )
    {
        gdprintk(XENLOG_INFO, "All CPUs offline -- powering off.\n");
        domain_shutdown(d, SHUTDOWN_poweroff);
    }
}

void hvm_hlt(unsigned int eflags)
{
    struct vcpu *curr = current;

    if ( hvm_event_pending(curr) )
        return;

    /*
     * If we halt with interrupts disabled, that's a pretty sure sign that we
     * want to shut down. In a real processor, NMIs are the only way to break
     * out of this.
     */
    if ( unlikely(!(eflags & X86_EFLAGS_IF)) )
        return hvm_vcpu_down(curr);

    do_sched_op(SCHEDOP_block, guest_handle_from_ptr(NULL, void));

    HVMTRACE_1D(HLT, /* pending = */ vcpu_runnable(curr));
}

void hvm_triple_fault(void)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    u8 reason = d->arch.hvm.params[HVM_PARAM_TRIPLE_FAULT_REASON];

    gprintk(XENLOG_ERR,
            "Triple fault - invoking HVM shutdown action %d\n",
            reason);
    vcpu_show_execution_state(v);
    domain_shutdown(d, reason);
}

void hvm_inject_event(const struct x86_event *event)
{
    struct vcpu *curr = current;
    const uint8_t vector = event->vector;
    const bool has_ec = ((event->type == X86_EVENTTYPE_HW_EXCEPTION) &&
                         (vector < 32) && ((TRAP_HAVE_EC & (1u << vector))));

    ASSERT(vector == event->vector); /* Confirm no truncation. */
    if ( has_ec )
        ASSERT(event->error_code != X86_EVENT_NO_EC);
    else
        ASSERT(event->error_code == X86_EVENT_NO_EC);

    if ( nestedhvm_enabled(curr->domain) &&
         !nestedhvm_vmswitch_in_progress(curr) &&
         nestedhvm_vcpu_in_guestmode(curr) &&
         nhvm_vmcx_guest_intercepts_event(
             curr, event->vector, event->error_code) )
    {
        enum nestedhvm_vmexits nsret;

        nsret = nhvm_vcpu_vmexit_event(curr, event);

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

    alternative_vcall(hvm_funcs.inject_event, event);
}

int hvm_hap_nested_page_fault(paddr_t gpa, unsigned long gla,
                              struct npfec npfec)
{
    unsigned long gfn = gpa >> PAGE_SHIFT;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    mfn_t mfn;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct p2m_domain *p2m, *hostp2m;
    int rc, fall_through = 0, paged = 0;
    int sharing_enomem = 0;
    vm_event_request_t *req_ptr = NULL;
    bool_t ap2m_active, sync = 0;
    unsigned int page_order;

    /* On Nested Virtualization, walk the guest page table.
     * If this succeeds, all is fine.
     * If this fails, inject a nested page fault into the guest.
     */
    if ( nestedhvm_enabled(currd)
        && nestedhvm_vcpu_in_guestmode(curr)
        && nestedhvm_paging_mode_hap(curr) )
    {
        int rv;

        /* The vcpu is in guest mode and the l1 guest
         * uses hap. That means 'gpa' is in l2 guest
         * physical address space.
         * Fix the nested p2m or inject nested page fault
         * into l1 guest if not fixable. The algorithm is
         * the same as for shadow paging.
         */

         rv = nestedhvm_hap_nested_page_fault(curr, &gpa,
                                              npfec.read_access,
                                              npfec.write_access,
                                              npfec.insn_fetch);
        switch (rv) {
        case NESTEDHVM_PAGEFAULT_DONE:
        case NESTEDHVM_PAGEFAULT_RETRY:
            return 1;
        case NESTEDHVM_PAGEFAULT_L1_ERROR:
            /* An error occurred while translating gpa from
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

    /*
     * No need to do the P2M lookup for internally handled MMIO, benefiting
     * - 32-bit WinXP (& older Windows) on AMD CPUs for LAPIC accesses,
     * - newer Windows (like Server 2012) for HPET accesses.
     */
    if ( !nestedhvm_vcpu_in_guestmode(curr) && hvm_mmio_internal(gpa) )
    {
        if ( !handle_mmio_with_translation(gla, gpa >> PAGE_SHIFT, npfec) )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out;
    }

    ap2m_active = altp2m_active(currd);

    /*
     * Take a lock on the host p2m speculatively, to avoid potential
     * locking order problems later and to handle unshare etc.
     */
    hostp2m = p2m_get_hostp2m(currd);
    mfn = get_gfn_type_access(hostp2m, gfn, &p2mt, &p2ma,
                              P2M_ALLOC | (npfec.write_access ? P2M_UNSHARE : 0),
                              &page_order);

    if ( ap2m_active )
    {
        p2m = p2m_get_altp2m(curr);

        /* 
         * Get the altp2m entry if present; or if not, propagate from
         * the host p2m.  NB that this returns with gfn locked in the
         * altp2m.
         */
        if ( p2m_altp2m_get_or_propagate(p2m, gfn, &mfn, &p2mt, &p2ma, page_order) )
        {
            /* Entry was copied from host -- retry fault */
            rc = 1;
            goto out_put_gfn;
        }
    }
    else
        p2m = hostp2m;

    /* Check access permissions first, then handle faults */
    if ( !mfn_eq(mfn, INVALID_MFN) )
    {
        bool_t violation;

        /* If the access is against the permissions, then send to vm_event */
        switch (p2ma)
        {
        case p2m_access_n:
        case p2m_access_n2rwx:
        default:
            violation = npfec.read_access || npfec.write_access || npfec.insn_fetch;
            break;
        case p2m_access_r:
            violation = npfec.write_access || npfec.insn_fetch;
            break;
        case p2m_access_w:
            violation = npfec.read_access || npfec.insn_fetch;
            break;
        case p2m_access_x:
            violation = npfec.read_access || npfec.write_access;
            break;
        case p2m_access_rx:
        case p2m_access_rx2rw:
            violation = npfec.write_access;
            break;
        case p2m_access_wx:
            violation = npfec.read_access;
            break;
        case p2m_access_rw:
            violation = npfec.insn_fetch;
            break;
        case p2m_access_rwx:
            violation = 0;
            break;
        }

        if ( violation )
        {
            /* Should #VE be emulated for this fault? */
            if ( p2m_is_altp2m(p2m) && !cpu_has_vmx_virt_exceptions )
            {
                bool_t sve;

                p2m->get_entry(p2m, _gfn(gfn), &p2mt, &p2ma, 0, NULL, &sve);

                if ( !sve && altp2m_vcpu_emulate_ve(curr) )
                {
                    rc = 1;
                    goto out_put_gfn;
                }
            }

            sync = p2m_mem_access_check(gpa, gla, npfec, &req_ptr);

            if ( !sync )
                fall_through = 1;
            else
            {
                /* Rights not promoted (aka. sync event), work here is done */
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
         (npfec.write_access &&
          (p2m_is_discard_write(p2mt) || (p2mt == p2m_ioreq_server))) )
    {
        if ( !handle_mmio_with_translation(gla, gpa >> PAGE_SHIFT, npfec) )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out_put_gfn;
    }

    /* Check if the page has been paged out */
    if ( p2m_is_paged(p2mt) || (p2mt == p2m_ram_paging_out) )
        paged = 1;

    /* Mem sharing: unshare the page and try again */
    if ( npfec.write_access && (p2mt == p2m_ram_shared) )
    {
        ASSERT(p2m_is_hostp2m(p2m));
        sharing_enomem = 
            (mem_sharing_unshare_page(currd, gfn, 0) < 0);
        rc = 1;
        goto out_put_gfn;
    }
 
    /* Spurious fault? PoD and log-dirty also take this path. */
    if ( p2m_is_ram(p2mt) )
    {
        rc = 1;
        /*
         * Page log dirty is always done with order 0. If this mfn resides in
         * a large page, we do not change other pages type within that large
         * page.
         */
        if ( npfec.write_access )
        {
            paging_mark_pfn_dirty(currd, _pfn(gfn));
            /*
             * If p2m is really an altp2m, unlock here to avoid lock ordering
             * violation when the change below is propagated from host p2m.
             */
            if ( ap2m_active )
                __put_gfn(p2m, gfn);
            p2m_change_type_one(currd, gfn, p2m_ram_logdirty, p2m_ram_rw);
            __put_gfn(ap2m_active ? hostp2m : p2m, gfn);

            goto out;
        }
        goto out_put_gfn;
    }

    if ( (p2mt == p2m_mmio_direct) && is_hardware_domain(currd) &&
         npfec.write_access && npfec.present &&
         (hvm_emulate_one_mmio(mfn_x(mfn), gla) == X86EMUL_OKAY) )
    {
        rc = 1;
        goto out_put_gfn;
    }

    /* If we fell through, the vcpu will retry now that access restrictions have
     * been removed. It may fault again if the p2m entry type still requires so.
     * Otherwise, this is an error condition. */
    rc = fall_through;

 out_put_gfn:
    __put_gfn(p2m, gfn);
    if ( ap2m_active )
        __put_gfn(hostp2m, gfn);
 out:
    /* All of these are delayed until we exit, since we might 
     * sleep on event ring wait queues, and we must not hold
     * locks in such circumstance */
    if ( paged )
        p2m_mem_paging_populate(currd, gfn);
    if ( sharing_enomem )
    {
        int rv;

        if ( (rv = mem_sharing_notify_enomem(currd, gfn, true)) < 0 )
        {
            gdprintk(XENLOG_ERR, "Domain %hu attempt to unshare "
                     "gfn %lx, ENOMEM and no helper (rc %d)\n",
                     currd->domain_id, gfn, rv);
            /* Crash the domain */
            rc = 0;
        }
    }
    if ( req_ptr )
    {
        if ( monitor_traps(curr, sync, req_ptr) < 0 )
            rc = 0;

        xfree(req_ptr);
    }
    return rc;
}

int hvm_handle_xsetbv(u32 index, u64 new_bv)
{
    int rc;

    if ( index == 0 )
        hvm_monitor_crX(XCR0, new_bv, current->arch.xcr0);

    rc = x86emul_write_xcr(index, new_bv, NULL);
    if ( rc != X86EMUL_OKAY )
        hvm_inject_hw_exception(TRAP_gp_fault, 0);

    return rc;
}

int hvm_set_efer(uint64_t value)
{
    struct vcpu *v = current;
    const char *errstr;

    value &= ~EFER_LMA;

    errstr = hvm_efer_valid(v, value, -1);
    if ( errstr )
    {
        printk(XENLOG_G_WARNING
               "%pv: Invalid EFER update: %#"PRIx64" -> %#"PRIx64" - %s\n",
               v, v->arch.hvm.guest_efer, value, errstr);
        return X86EMUL_EXCEPTION;
    }

    if ( ((value ^ v->arch.hvm.guest_efer) & EFER_LME) &&
         hvm_paging_enabled(v) )
    {
        gdprintk(XENLOG_WARNING,
                 "Trying to change EFER.LME with paging enabled\n");
        return X86EMUL_EXCEPTION;
    }

    if ( (value & EFER_LME) && !(v->arch.hvm.guest_efer & EFER_LME) )
    {
        struct segment_register cs;

        hvm_get_segment_register(v, x86_seg_cs, &cs);

        /*
         * %cs may be loaded with both .D and .L set in legacy mode, and both
         * are captured in the VMCS/VMCB.
         *
         * If a guest does this and then tries to transition into long mode,
         * the vmentry from setting LME fails due to invalid guest state,
         * because %cr0.PG is still clear.
         *
         * When LME becomes set, clobber %cs.L to keep the guest firmly in
         * compatibility mode until it reloads %cs itself.
         */
        if ( cs.l )
        {
            cs.l = 0;
            hvm_set_segment_register(v, x86_seg_cs, &cs);
        }
    }

    if ( nestedhvm_enabled(v->domain) && cpu_has_svm &&
       ((value & EFER_SVME) == 0 ) &&
       ((value ^ v->arch.hvm.guest_efer) & EFER_SVME) )
    {
        /* Cleared EFER.SVME: Flush all nestedp2m tables */
        p2m_flush_nestedp2m(v->domain);
        nestedhvm_vcpu_reset(v);
    }

    value |= v->arch.hvm.guest_efer & EFER_LMA;
    v->arch.hvm.guest_efer = value;
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
        if ( (vs->arch.hvm.cache_mode == NO_FILL_CACHE_MODE) ||
             mtrr_pat_not_equal(vs, v) )
            return 0;
    }

    return 1;
}

static void hvm_set_uc_mode(struct vcpu *v, bool_t is_in_uc_mode)
{
    v->domain->arch.hvm.is_in_uc_mode = is_in_uc_mode;
    shadow_blow_tables_per_domain(v->domain);
}

int hvm_mov_to_cr(unsigned int cr, unsigned int gpr)
{
    struct vcpu *curr = current;
    unsigned long val = *decode_gpr(guest_cpu_user_regs(), gpr);
    int rc;

    HVMTRACE_LONG_2D(CR_WRITE, cr, TRC_PAR_LONG(val));
    HVM_DBG_LOG(DBG_LEVEL_1, "CR%u, value = %lx", cr, val);

    switch ( cr )
    {
    case 0:
        rc = hvm_set_cr0(val, true);
        break;

    case 3:
        rc = hvm_set_cr3(val, true);
        break;

    case 4:
        rc = hvm_set_cr4(val, true);
        break;

    case 8:
        vlapic_set_reg(vcpu_vlapic(curr), APIC_TASKPRI, ((val & 0x0f) << 4));
        rc = X86EMUL_OKAY;
        break;

    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        goto exit_and_crash;
    }

    if ( rc == X86EMUL_EXCEPTION )
        hvm_inject_hw_exception(TRAP_gp_fault, 0);

    return rc;

 exit_and_crash:
    domain_crash(curr->domain);
    return X86EMUL_UNHANDLEABLE;
}

int hvm_mov_from_cr(unsigned int cr, unsigned int gpr)
{
    struct vcpu *curr = current;
    unsigned long val = 0, *reg = decode_gpr(guest_cpu_user_regs(), gpr);

    switch ( cr )
    {
    case 0:
    case 2:
    case 3:
    case 4:
        val = array_access_nospec(curr->arch.hvm.guest_cr, cr);
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
        spin_lock(&v->domain->arch.hvm.uc_lock);
        v->arch.hvm.cache_mode = NO_FILL_CACHE_MODE;

        if ( !v->domain->arch.hvm.is_in_uc_mode )
        {
            domain_pause_nosync(v->domain);

            /* Flush physical caches. */
            flush_all(FLUSH_CACHE);
            hvm_set_uc_mode(v, 1);

            domain_unpause(v->domain);
        }
        spin_unlock(&v->domain->arch.hvm.uc_lock);
    }
    else if ( !(value & X86_CR0_CD) &&
              (v->arch.hvm.cache_mode == NO_FILL_CACHE_MODE) )
    {
        /* Exit from no fill cache mode. */
        spin_lock(&v->domain->arch.hvm.uc_lock);
        v->arch.hvm.cache_mode = NORMAL_CACHE_MODE;

        if ( domain_exit_uc_mode(v) )
            hvm_set_uc_mode(v, 0);

        spin_unlock(&v->domain->arch.hvm.uc_lock);
    }
}

static void hvm_update_cr(struct vcpu *v, unsigned int cr, unsigned long value)
{
    v->arch.hvm.guest_cr[cr] = value;
    nestedhvm_set_cr(v, cr, value);
    hvm_update_guest_cr(v, cr);
}

int hvm_set_cr0(unsigned long value, bool may_defer)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long gfn, old_value = v->arch.hvm.guest_cr[0];
    struct page_info *page;

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx", value);

    if ( (u32)value != value )
    {
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Guest attempts to set upper 32 bits in CR0: %lx",
                    value);
        return X86EMUL_EXCEPTION;
    }

    value &= ~HVM_CR0_GUEST_RESERVED_BITS;

    /* ET is reserved and should be always be 1. */
    value |= X86_CR0_ET;

    if ( !nestedhvm_vmswitch_in_progress(v) &&
         (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PG )
        return X86EMUL_EXCEPTION;

    if ( may_defer && unlikely(v->domain->arch.monitor.write_ctrlreg_enabled &
                               monitor_ctrlreg_bitmask(VM_EVENT_X86_CR0)) )
    {
        ASSERT(v->arch.vm_event);

        if ( hvm_monitor_crX(CR0, value, old_value) )
        {
            /* The actual write will occur in hvm_do_resume(), if permitted. */
            v->arch.vm_event->write_data.do_write.cr0 = 1;
            v->arch.vm_event->write_data.cr0 = value;

            return X86EMUL_OKAY;
        }
    }

    if ( (value & X86_CR0_PG) && !(old_value & X86_CR0_PG) )
    {
        if ( v->arch.hvm.guest_efer & EFER_LME )
        {
            if ( !(v->arch.hvm.guest_cr[4] & X86_CR4_PAE) &&
                 !nestedhvm_vmswitch_in_progress(v) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enable");
                return X86EMUL_EXCEPTION;
            }
            HVM_DBG_LOG(DBG_LEVEL_1, "Enabling long mode");
            v->arch.hvm.guest_efer |= EFER_LMA;
            hvm_update_guest_efer(v);
        }

        if ( !paging_mode_hap(d) )
        {
            /* The guest CR3 must be pointing to the guest physical. */
            gfn = v->arch.hvm.guest_cr[3] >> PAGE_SHIFT;
            page = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
            if ( !page )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value = %lx\n",
                         v->arch.hvm.guest_cr[3]);
                domain_crash(d);
                return X86EMUL_UNHANDLEABLE;
            }

            /* Now arch.guest_table points to machine physical. */
            v->arch.guest_table = pagetable_from_page(page);

            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                        v->arch.hvm.guest_cr[3], mfn_x(page_to_mfn(page)));
        }
    }
    else if ( !(value & X86_CR0_PG) && (old_value & X86_CR0_PG) )
    {
        if ( hvm_pcid_enabled(v) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Guest attempts to clear CR0.PG "
                        "while CR4.PCIDE=1");
            return X86EMUL_EXCEPTION;
        }

        /* When CR0.PG is cleared, LMA is cleared immediately. */
        if ( hvm_long_mode_active(v) )
        {
            v->arch.hvm.guest_efer &= ~EFER_LMA;
            hvm_update_guest_efer(v);
        }

        if ( !paging_mode_hap(d) )
        {
            put_page(pagetable_get_page(v->arch.guest_table));
            v->arch.guest_table = pagetable_null();
        }
    }

    if ( ((value ^ old_value) & X86_CR0_CD) &&
         iommu_enabled && hvm_funcs.handle_cd &&
         (!rangeset_is_empty(d->iomem_caps) ||
          !rangeset_is_empty(d->arch.ioport_caps) ||
          has_arch_pdevs(d)) )
        alternative_vcall(hvm_funcs.handle_cd, v, value);

    hvm_update_cr(v, 0, value);

    if ( (value ^ old_value) & X86_CR0_PG ) {
        if ( !nestedhvm_vmswitch_in_progress(v) && nestedhvm_vcpu_in_guestmode(v) )
            paging_update_nestedmode(v);
        else
            paging_update_paging_modes(v);
    }

    return X86EMUL_OKAY;
}

int hvm_set_cr3(unsigned long value, bool may_defer)
{
    struct vcpu *v = current;
    struct page_info *page;
    unsigned long old = v->arch.hvm.guest_cr[3];
    bool noflush = false;

    if ( may_defer && unlikely(v->domain->arch.monitor.write_ctrlreg_enabled &
                               monitor_ctrlreg_bitmask(VM_EVENT_X86_CR3)) )
    {
        ASSERT(v->arch.vm_event);

        if ( hvm_monitor_crX(CR3, value, old) )
        {
            /* The actual write will occur in hvm_do_resume(), if permitted. */
            v->arch.vm_event->write_data.do_write.cr3 = 1;
            v->arch.vm_event->write_data.cr3 = value;

            return X86EMUL_OKAY;
        }
    }

    if ( hvm_pcid_enabled(v) ) /* Clear the noflush bit. */
    {
        noflush = value & X86_CR3_NOFLUSH;
        value &= ~X86_CR3_NOFLUSH;
    }

    if ( hvm_paging_enabled(v) && !paging_mode_hap(v->domain) &&
         (value != v->arch.hvm.guest_cr[3]) )
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

    v->arch.hvm.guest_cr[3] = value;
    paging_update_cr3(v, noflush);
    return X86EMUL_OKAY;

 bad_cr3:
    gdprintk(XENLOG_ERR, "Invalid CR3\n");
    domain_crash(v->domain);
    return X86EMUL_UNHANDLEABLE;
}

int hvm_set_cr4(unsigned long value, bool may_defer)
{
    struct vcpu *v = current;
    unsigned long old_cr;

    if ( value & ~hvm_cr4_guest_valid_bits(v->domain, false) )
    {
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Guest attempts to set reserved bit in CR4: %lx",
                    value);
        return X86EMUL_EXCEPTION;
    }

    if ( !(value & X86_CR4_PAE) )
    {
        if ( hvm_long_mode_active(v) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Guest cleared CR4.PAE while "
                        "EFER.LMA is set");
            return X86EMUL_EXCEPTION;
        }
    }

    old_cr = v->arch.hvm.guest_cr[4];

    if ( (value & X86_CR4_PCIDE) && !(old_cr & X86_CR4_PCIDE) &&
         (!hvm_long_mode_active(v) ||
          (v->arch.hvm.guest_cr[3] & 0xfff)) )
    {
        HVM_DBG_LOG(DBG_LEVEL_1, "Guest attempts to change CR4.PCIDE from "
                    "0 to 1 while either EFER.LMA=0 or CR3[11:0]!=000H");
        return X86EMUL_EXCEPTION;
    }

    if ( may_defer && unlikely(v->domain->arch.monitor.write_ctrlreg_enabled &
                               monitor_ctrlreg_bitmask(VM_EVENT_X86_CR4)) )
    {
        ASSERT(v->arch.vm_event);

        if ( hvm_monitor_crX(CR4, value, old_cr) )
        {
            /* The actual write will occur in hvm_do_resume(), if permitted. */
            v->arch.vm_event->write_data.do_write.cr4 = 1;
            v->arch.vm_event->write_data.cr4 = value;

            return X86EMUL_OKAY;
        }
    }

    hvm_update_cr(v, 4, value);

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

    /*
     * {RD,WR}PKRU are not gated on XCR0.PKRU and hence an oddly behaving
     * guest may enable the feature in CR4 without enabling it in XCR0. We
     * need to context switch / migrate PKRU nevertheless.
     */
    if ( (value & X86_CR4_PKE) && !(v->arch.xcr0_accum & X86_XCR0_PKRU) )
    {
        int rc = handle_xsetbv(XCR_XFEATURE_ENABLED_MASK,
                               get_xcr0() | X86_XCR0_PKRU);

        if ( rc )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Failed to force XCR0.PKRU: %d", rc);
            return X86EMUL_EXCEPTION;
        }

        if ( handle_xsetbv(XCR_XFEATURE_ENABLED_MASK,
                           get_xcr0() & ~X86_XCR0_PKRU) )
            /* nothing, best effort only */;
    }

    return X86EMUL_OKAY;
}

bool_t hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    const struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    const struct segment_register *active_cs,
    unsigned long *linear_addr)
{
    const struct vcpu *curr = current;
    unsigned long addr = offset, last_byte;
    bool_t okay = 0;

    /*
     * These checks are for a memory access through an active segment.
     *
     * It is expected that the access rights of reg are suitable for seg (and
     * that this is enforced at the point that seg is loaded).
     */
    ASSERT(seg < x86_seg_none);

    if ( !(curr->arch.hvm.guest_cr[0] & X86_CR0_PE) )
    {
        /*
         * REAL MODE: Don't bother with segment access checks.
         * Certain of them are not done in native real mode anyway.
         */
        addr = (uint32_t)(addr + reg->base);
    }
    else if ( (guest_cpu_user_regs()->eflags & X86_EFLAGS_VM) &&
              is_x86_user_segment(seg) )
    {
        /* VM86 MODE: Fixed 64k limits on all user segments. */
        addr = (uint32_t)(addr + reg->base);
        last_byte = (uint32_t)offset + bytes - !!bytes;
        if ( max(offset, last_byte) >> 16 )
            goto out;
    }
    else if ( hvm_long_mode_active(curr) &&
              (is_x86_system_segment(seg) || active_cs->l) )
    {
        /*
         * User segments are always treated as present.  System segment may
         * not be, and also incur limit checks.
         */
        if ( is_x86_system_segment(seg) &&
             (!reg->p || (offset + bytes - !!bytes) > reg->limit) )
            goto out;

        /*
         * LONG MODE: FS, GS and system segments: add segment base. All
         * addresses must be canonical.
         */
        if ( seg >= x86_seg_fs )
            addr += reg->base;

        last_byte = addr + bytes - !!bytes;
        if ( !is_canonical_address((long)addr < 0 ? addr : last_byte) )
            goto out;
    }
    else
    {
        /*
         * PROTECTED/COMPATIBILITY MODE: Apply segment checks and add base.
         */

        /*
         * Hardware truncates to 32 bits in compatibility mode.
         * It does not truncate to 16 bits in 16-bit address-size mode.
         */
        addr = (uint32_t)(addr + reg->base);

        /* Segment not valid for use (cooked meaning of .p)? */
        if ( !reg->p )
            goto out;

        /* Read/write restrictions only exist for user segments. */
        if ( reg->s )
        {
            switch ( access_type )
            {
            case hvm_access_read:
                if ( (reg->type & 0xa) == 0x8 )
                    goto out; /* execute-only code segment */
                break;
            case hvm_access_write:
                if ( (reg->type & 0xa) != 0x2 )
                    goto out; /* not a writable data segment */
                break;
            default:
                break;
            }
        }

        last_byte = (uint32_t)offset + bytes - !!bytes;

        /* Is this a grows-down data segment? Special limit check if so. */
        if ( reg->s && (reg->type & 0xc) == 0x4 )
        {
            /* Is upper limit 0xFFFF or 0xFFFFFFFF? */
            if ( !reg->db )
                last_byte = (uint16_t)last_byte;

            /* Check first byte and last byte against respective bounds. */
            if ( (offset <= reg->limit) || (last_byte < offset) )
                goto out;
        }
        else if ( last_byte > reg->limit )
            goto out; /* last byte is beyond limit */
        else if ( last_byte < offset &&
                  curr->domain->arch.cpuid->x86_vendor == X86_VENDOR_AMD )
            goto out; /* access wraps */
    }

    /* All checks ok. */
    okay = 1;

 out:
    /*
     * Always return the correct linear address, even if a permission check
     * failed.  The permissions failure is not relevant to some callers.
     */
    *linear_addr = addr;
    return okay;
}

struct hvm_write_map {
    struct list_head list;
    struct page_info *page;
};

/* On non-NULL return, we leave this function holding an additional 
 * ref on the underlying mfn, if any */
static void *_hvm_map_guest_frame(unsigned long gfn, bool_t permanent,
                                  bool_t *writable)
{
    void *map;
    p2m_type_t p2mt;
    struct page_info *page;
    struct domain *d = current->domain;

    if ( check_get_page_from_gfn(d, _gfn(gfn), !writable, &p2mt, &page) )
        return NULL;

    if ( writable )
    {
        if ( unlikely(p2m_is_discard_write(p2mt)) ||
             unlikely(p2mt == p2m_ioreq_server) )
            *writable = 0;
        else if ( !permanent )
            paging_mark_pfn_dirty(d, _pfn(gfn));
    }

    if ( !permanent )
        return __map_domain_page(page);

    if ( writable && *writable )
    {
        struct hvm_write_map *track = xmalloc(struct hvm_write_map);

        if ( !track )
        {
            put_page(page);
            return NULL;
        }
        track->page = page;
        spin_lock(&d->arch.hvm.write_map.lock);
        list_add_tail(&track->list, &d->arch.hvm.write_map.list);
        spin_unlock(&d->arch.hvm.write_map.lock);
    }

    map = __map_domain_page_global(page);
    if ( !map )
        put_page(page);

    return map;
}

void *hvm_map_guest_frame_rw(unsigned long gfn, bool_t permanent,
                             bool_t *writable)
{
    *writable = 1;
    return _hvm_map_guest_frame(gfn, permanent, writable);
}

void *hvm_map_guest_frame_ro(unsigned long gfn, bool_t permanent)
{
    return _hvm_map_guest_frame(gfn, permanent, NULL);
}

void hvm_unmap_guest_frame(void *p, bool_t permanent)
{
    mfn_t mfn;
    struct page_info *page;

    if ( !p )
        return;

    mfn = domain_page_map_to_mfn(p);
    page = mfn_to_page(mfn);

    if ( !permanent )
        unmap_domain_page(p);
    else
    {
        struct domain *d = page_get_owner(page);
        struct hvm_write_map *track;

        unmap_domain_page_global(p);
        spin_lock(&d->arch.hvm.write_map.lock);
        list_for_each_entry(track, &d->arch.hvm.write_map.list, list)
            if ( track->page == page )
            {
                paging_mark_dirty(d, mfn);
                list_del(&track->list);
                xfree(track);
                break;
            }
        spin_unlock(&d->arch.hvm.write_map.lock);
    }

    put_page(page);
}

void hvm_mapped_guest_frames_mark_dirty(struct domain *d)
{
    struct hvm_write_map *track;

    spin_lock(&d->arch.hvm.write_map.lock);
    list_for_each_entry(track, &d->arch.hvm.write_map.list, list)
        paging_mark_dirty(d, page_to_mfn(track->page));
    spin_unlock(&d->arch.hvm.write_map.lock);
}

static void *hvm_map_entry(unsigned long va, bool_t *writable)
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
    if ( pfec & (PFEC_page_paged | PFEC_page_shared) )
        goto fail;

    v = hvm_map_guest_frame_rw(gfn, 0, writable);
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

static int task_switch_load_seg(
    enum x86_segment seg, uint16_t sel, unsigned int cpl, unsigned int eflags)
{
    struct segment_register desctab, segr;
    seg_desc_t *pdesc = NULL, desc;
    u8 dpl, rpl;
    bool_t writable;
    int fault_type = TRAP_invalid_tss;
    struct vcpu *v = current;

    if ( eflags & X86_EFLAGS_VM )
    {
        segr.sel = sel;
        segr.base = (uint32_t)sel << 4;
        segr.limit = 0xffffu;
        segr.attr = 0xf3;
        hvm_set_segment_register(v, seg, &segr);
        return 0;
    }

    /* NULL selector? */
    if ( (sel & 0xfffc) == 0 )
    {
        if ( (seg == x86_seg_cs) || (seg == x86_seg_ss) )
            goto fault;
        memset(&segr, 0, sizeof(segr));
        segr.sel = sel;
        hvm_set_segment_register(v, seg, &segr);
        return 0;
    }

    /* LDT descriptor must be in the GDT. */
    if ( (seg == x86_seg_ldtr) && (sel & 4) )
        goto fault;

    hvm_get_segment_register(
        v, (sel & 4) ? x86_seg_ldtr : x86_seg_gdtr, &desctab);

    /* Segment not valid for use (cooked meaning of .p)? */
    if ( !desctab.p )
        goto fault;

    /* Check against descriptor table limit. */
    if ( ((sel & 0xfff8) + 7) > desctab.limit )
        goto fault;

    pdesc = hvm_map_entry(desctab.base + (sel & 0xfff8), &writable);
    if ( pdesc == NULL )
        goto fault;

    do {
        desc = *pdesc;

        /* LDT descriptor is a system segment. All others are code/data. */
        if ( (desc.b & (1u<<12)) == ((seg == x86_seg_ldtr) << 12) )
            goto fault;

        dpl = (desc.b >> 13) & 3;
        rpl = sel & 3;

        switch ( seg )
        {
        case x86_seg_cs:
            /* Code segment? */
            if ( !(desc.b & _SEGMENT_CODE) )
                goto fault;
            /* Non-conforming segment: check DPL against RPL. */
            if ( !(desc.b & _SEGMENT_EC) && (dpl != rpl) )
                goto fault;
            break;
        case x86_seg_ss:
            /* Writable data segment? */
            if ( (desc.b & (_SEGMENT_CODE|_SEGMENT_WR)) != _SEGMENT_WR )
                goto fault;
            if ( (dpl != cpl) || (dpl != rpl) )
                goto fault;
            break;
        case x86_seg_ldtr:
            /* LDT system segment? */
            if ( (desc.b & _SEGMENT_TYPE) != (2u<<8) )
                goto fault;
            goto skip_accessed_flag;
        default:
            /* Readable code or data segment? */
            if ( (desc.b & (_SEGMENT_CODE|_SEGMENT_WR)) == _SEGMENT_CODE )
                goto fault;
            /*
             * Data or non-conforming code segment:
             * check DPL against RPL and CPL.
             */
            if ( ((desc.b & (_SEGMENT_EC|_SEGMENT_CODE)) !=
                  (_SEGMENT_EC|_SEGMENT_CODE))
                 && ((dpl < cpl) || (dpl < rpl)) )
                goto fault;
            break;
        }

        /* Segment present in memory? */
        if ( !(desc.b & _SEGMENT_P) )
        {
            fault_type = (seg != x86_seg_ss) ? TRAP_no_segment
                                             : TRAP_stack_error;
            goto fault;
        }
    } while ( !(desc.b & 0x100) && /* Ensure Accessed flag is set */
              writable && /* except if we are to discard writes */
              (cmpxchg(&pdesc->b, desc.b, desc.b | 0x100) != desc.b) );

    /* Force the Accessed flag in our local copy. */
    desc.b |= 0x100;

 skip_accessed_flag:
    hvm_unmap_entry(pdesc);

    segr.base = (((desc.b <<  0) & 0xff000000u) |
                 ((desc.b << 16) & 0x00ff0000u) |
                 ((desc.a >> 16) & 0x0000ffffu));
    segr.attr = (((desc.b >>  8) & 0x00ffu) |
                 ((desc.b >> 12) & 0x0f00u));
    segr.limit = (desc.b & 0x000f0000u) | (desc.a & 0x0000ffffu);
    if ( segr.g )
        segr.limit = (segr.limit << 12) | 0xfffu;
    segr.sel = sel;
    hvm_set_segment_register(v, seg, &segr);

    return 0;

 fault:
    hvm_unmap_entry(pdesc);
    hvm_inject_hw_exception(fault_type, sel & 0xfffc);

    return 1;
}

struct tss32 {
    uint16_t back_link, :16;
    uint32_t esp0;
    uint16_t ss0, :16;
    uint32_t esp1;
    uint16_t ss1, :16;
    uint32_t esp2;
    uint16_t ss2, :16;
    uint32_t cr3, eip, eflags, eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint16_t es, :16, cs, :16, ss, :16, ds, :16, fs, :16, gs, :16, ldt, :16;
    uint16_t trace /* :1 */, iomap;
};

void hvm_prepare_vm86_tss(struct vcpu *v, uint32_t base, uint32_t limit)
{
    /*
     * If the provided area is large enough to cover at least the ISA port
     * range, keep the bitmaps outside the base structure. For rather small
     * areas (namely relevant for guests having been migrated from older
     * Xen versions), maximize interrupt vector and port coverage by pointing
     * the I/O bitmap at 0x20 (which puts the interrupt redirection bitmap
     * right at zero), accepting accesses to port 0x235 (represented by bit 5
     * of byte 0x46) to trigger #GP (which will simply result in the access
     * being handled by the emulator via a slightly different path than it
     * would be anyway). Be sure to include one extra byte at the end of the
     * I/O bitmap (hence the missing "- 1" in the comparison is not an
     * off-by-one mistake), which we deliberately don't fill with all ones.
     */
    uint16_t iomap = (limit >= sizeof(struct tss32) + (0x100 / 8) + (0x400 / 8)
                      ? sizeof(struct tss32) : 0) + (0x100 / 8);

    ASSERT(limit >= sizeof(struct tss32) - 1);
    /*
     * Strictly speaking we'd have to use hvm_copy_to_guest_linear() below,
     * but since the guest is (supposed to be, unless it corrupts that setup
     * itself, which would harm only itself) running on an identmap, we can
     * use the less overhead variant below, which also allows passing a vCPU
     * argument.
     */
    hvm_copy_to_guest_phys(base, NULL, limit + 1, v);
    hvm_copy_to_guest_phys(base + offsetof(struct tss32, iomap),
                           &iomap, sizeof(iomap), v);
}

void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode)
{
    struct vcpu *v = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct segment_register gdt, tr, prev_tr, segr;
    seg_desc_t *optss_desc = NULL, *nptss_desc = NULL, tss_desc;
    bool_t otd_writable, ntd_writable;
    unsigned int eflags, new_cpl;
    pagefault_info_t pfinfo;
    int exn_raised, rc;
    struct tss32 tss;

    hvm_get_segment_register(v, x86_seg_gdtr, &gdt);
    hvm_get_segment_register(v, x86_seg_tr, &prev_tr);

    if ( ((tss_sel & 0xfff8) + 7) > gdt.limit )
    {
        hvm_inject_hw_exception((taskswitch_reason == TSW_iret) ?
                             TRAP_invalid_tss : TRAP_gp_fault,
                             tss_sel & 0xfff8);
        goto out;
    }

    optss_desc = hvm_map_entry(gdt.base + (prev_tr.sel & 0xfff8),
                               &otd_writable);
    if ( optss_desc == NULL )
        goto out;

    nptss_desc = hvm_map_entry(gdt.base + (tss_sel & 0xfff8), &ntd_writable);
    if ( nptss_desc == NULL )
        goto out;

    tss_desc = *nptss_desc;
    tr.sel = tss_sel;
    tr.base = (((tss_desc.b <<  0) & 0xff000000u) |
               ((tss_desc.b << 16) & 0x00ff0000u) |
               ((tss_desc.a >> 16) & 0x0000ffffu));
    tr.attr = (((tss_desc.b >>  8) & 0x00ffu) |
               ((tss_desc.b >> 12) & 0x0f00u));
    tr.limit = (tss_desc.b & 0x000f0000u) | (tss_desc.a & 0x0000ffffu);
    if ( tr.g )
        tr.limit = (tr.limit << 12) | 0xfffu;

    if ( tr.type != ((taskswitch_reason == TSW_iret) ? 0xb : 0x9) )
    {
        hvm_inject_hw_exception(
            (taskswitch_reason == TSW_iret) ? TRAP_invalid_tss : TRAP_gp_fault,
            tss_sel & 0xfff8);
        goto out;
    }

    if ( !tr.p )
    {
        hvm_inject_hw_exception(TRAP_no_segment, tss_sel & 0xfff8);
        goto out;
    }

    if ( tr.limit < (sizeof(tss)-1) )
    {
        hvm_inject_hw_exception(TRAP_invalid_tss, tss_sel & 0xfff8);
        goto out;
    }

    rc = hvm_copy_from_guest_linear(
        &tss, prev_tr.base, sizeof(tss), PFEC_page_present, &pfinfo);
    if ( rc == HVMTRANS_bad_linear_to_gfn )
        hvm_inject_page_fault(pfinfo.ec, pfinfo.linear);
    if ( rc != HVMTRANS_okay )
        goto out;

    eflags = regs->eflags;
    if ( taskswitch_reason == TSW_iret )
        eflags &= ~X86_EFLAGS_NT;

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

    rc = hvm_copy_to_guest_linear(prev_tr.base + offsetof(typeof(tss), eip),
                                  &tss.eip,
                                  offsetof(typeof(tss), trace) -
                                  offsetof(typeof(tss), eip),
                                  PFEC_page_present, &pfinfo);
    if ( rc == HVMTRANS_bad_linear_to_gfn )
        hvm_inject_page_fault(pfinfo.ec, pfinfo.linear);
    if ( rc != HVMTRANS_okay )
        goto out;

    rc = hvm_copy_from_guest_linear(
        &tss, tr.base, sizeof(tss), PFEC_page_present, &pfinfo);
    if ( rc == HVMTRANS_bad_linear_to_gfn )
        hvm_inject_page_fault(pfinfo.ec, pfinfo.linear);
    /*
     * Note: The HVMTRANS_gfn_shared case could be optimised, if the callee
     * functions knew we want RO access.
     */
    if ( rc != HVMTRANS_okay )
        goto out;

    new_cpl = tss.eflags & X86_EFLAGS_VM ? 3 : tss.cs & 3;

    if ( task_switch_load_seg(x86_seg_ldtr, tss.ldt, new_cpl, 0) )
        goto out;

    rc = hvm_set_cr3(tss.cr3, true);
    if ( rc == X86EMUL_EXCEPTION )
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
    if ( rc != X86EMUL_OKAY )
        goto out;

    regs->rip    = tss.eip;
    regs->rflags = tss.eflags | X86_EFLAGS_MBS;
    regs->rax    = tss.eax;
    regs->rcx    = tss.ecx;
    regs->rdx    = tss.edx;
    regs->rbx    = tss.ebx;
    regs->rsp    = tss.esp;
    regs->rbp    = tss.ebp;
    regs->rsi    = tss.esi;
    regs->rdi    = tss.edi;

    exn_raised = 0;
    if ( task_switch_load_seg(x86_seg_es, tss.es, new_cpl, tss.eflags) ||
         task_switch_load_seg(x86_seg_cs, tss.cs, new_cpl, tss.eflags) ||
         task_switch_load_seg(x86_seg_ss, tss.ss, new_cpl, tss.eflags) ||
         task_switch_load_seg(x86_seg_ds, tss.ds, new_cpl, tss.eflags) ||
         task_switch_load_seg(x86_seg_fs, tss.fs, new_cpl, tss.eflags) ||
         task_switch_load_seg(x86_seg_gs, tss.gs, new_cpl, tss.eflags) )
        exn_raised = 1;

    if ( taskswitch_reason == TSW_call_or_int )
    {
        regs->eflags |= X86_EFLAGS_NT;
        tss.back_link = prev_tr.sel;

        rc = hvm_copy_to_guest_linear(tr.base + offsetof(typeof(tss), back_link),
                                      &tss.back_link, sizeof(tss.back_link), 0,
                                      &pfinfo);
        if ( rc == HVMTRANS_bad_linear_to_gfn )
        {
            hvm_inject_page_fault(pfinfo.ec, pfinfo.linear);
            exn_raised = 1;
        }
        else if ( rc != HVMTRANS_okay )
            goto out;
    }

    tr.type = 0xb; /* busy 32-bit tss */
    hvm_set_segment_register(v, x86_seg_tr, &tr);

    v->arch.hvm.guest_cr[0] |= X86_CR0_TS;
    hvm_update_guest_cr(v, 0);

    if ( (taskswitch_reason == TSW_iret ||
          taskswitch_reason == TSW_jmp) && otd_writable )
        clear_bit(41, optss_desc); /* clear B flag of old task */

    if ( taskswitch_reason != TSW_iret && ntd_writable )
        set_bit(41, nptss_desc); /* set B flag of new task */

    if ( errcode >= 0 )
    {
        struct segment_register cs;
        unsigned long linear_addr;
        unsigned int opsz, sp;

        hvm_get_segment_register(v, x86_seg_cs, &cs);
        opsz = cs.db ? 4 : 2;
        hvm_get_segment_register(v, x86_seg_ss, &segr);
        if ( segr.db )
            sp = regs->esp -= opsz;
        else
            sp = regs->sp -= opsz;
        if ( hvm_virtual_to_linear_addr(x86_seg_ss, &segr, sp, opsz,
                                        hvm_access_write,
                                        &cs, &linear_addr) )
        {
            rc = hvm_copy_to_guest_linear(linear_addr, &errcode, opsz, 0,
                                          &pfinfo);
            if ( rc == HVMTRANS_bad_linear_to_gfn )
            {
                hvm_inject_page_fault(pfinfo.ec, pfinfo.linear);
                exn_raised = 1;
            }
            else if ( rc != HVMTRANS_okay )
                goto out;
        }
    }

    if ( (tss.trace & 1) && !exn_raised )
        hvm_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);

 out:
    hvm_unmap_entry(optss_desc);
    hvm_unmap_entry(nptss_desc);
}

enum hvm_translation_result hvm_translate_get_page(
    struct vcpu *v, unsigned long addr, bool linear, uint32_t pfec,
    pagefault_info_t *pfinfo, struct page_info **page_p,
    gfn_t *gfn_p, p2m_type_t *p2mt_p)
{
    struct page_info *page;
    p2m_type_t p2mt;
    gfn_t gfn;

    if ( linear )
    {
        gfn = _gfn(paging_gva_to_gfn(v, addr, &pfec));

        if ( gfn_eq(gfn, INVALID_GFN) )
        {
            if ( pfec & PFEC_page_paged )
                return HVMTRANS_gfn_paged_out;

            if ( pfec & PFEC_page_shared )
                return HVMTRANS_gfn_shared;

            if ( pfinfo )
            {
                pfinfo->linear = addr;
                pfinfo->ec = pfec & ~PFEC_implicit;
            }

            return HVMTRANS_bad_linear_to_gfn;
        }
    }
    else
    {
        gfn = gaddr_to_gfn(addr);
        ASSERT(!pfinfo);
    }

    /*
     * No need to do the P2M lookup for internally handled MMIO, benefiting
     * - 32-bit WinXP (& older Windows) on AMD CPUs for LAPIC accesses,
     * - newer Windows (like Server 2012) for HPET accesses.
     */
    if ( v == current
         && !nestedhvm_vcpu_in_guestmode(v)
         && hvm_mmio_internal(gfn_to_gaddr(gfn)) )
        return HVMTRANS_bad_gfn_to_mfn;

    page = get_page_from_gfn(v->domain, gfn_x(gfn), &p2mt, P2M_UNSHARE);

    if ( !page )
        return HVMTRANS_bad_gfn_to_mfn;

    if ( p2m_is_paging(p2mt) )
    {
        put_page(page);
        p2m_mem_paging_populate(v->domain, gfn_x(gfn));
        return HVMTRANS_gfn_paged_out;
    }
    if ( p2m_is_shared(p2mt) )
    {
        put_page(page);
        return HVMTRANS_gfn_shared;
    }
    if ( p2m_is_grant(p2mt) )
    {
        put_page(page);
        return HVMTRANS_unhandleable;
    }

    *page_p = page;
    if ( gfn_p )
        *gfn_p = gfn;
    if ( p2mt_p )
        *p2mt_p = p2mt;

    return HVMTRANS_okay;
}

#define HVMCOPY_from_guest (0u<<0)
#define HVMCOPY_to_guest   (1u<<0)
#define HVMCOPY_phys       (0u<<2)
#define HVMCOPY_linear     (1u<<2)
static enum hvm_translation_result __hvm_copy(
    void *buf, paddr_t addr, int size, struct vcpu *v, unsigned int flags,
    uint32_t pfec, pagefault_info_t *pfinfo)
{
    gfn_t gfn;
    struct page_info *page;
    p2m_type_t p2mt;
    char *p;
    int count, todo = size;

    ASSERT(is_hvm_vcpu(v));

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
        return HVMTRANS_unhandleable;
#endif

    while ( todo > 0 )
    {
        enum hvm_translation_result res;
        paddr_t gpa = addr & ~PAGE_MASK;

        count = min_t(int, PAGE_SIZE - gpa, todo);

        res = hvm_translate_get_page(v, addr, flags & HVMCOPY_linear,
                                     pfec, pfinfo, &page, &gfn, &p2mt);
        if ( res != HVMTRANS_okay )
            return res;

        if ( (flags & HVMCOPY_to_guest) && p2mt == p2m_ioreq_server )
        {
            put_page(page);
            return HVMTRANS_bad_gfn_to_mfn;
        }

        p = (char *)__map_domain_page(page) + (addr & ~PAGE_MASK);

        if ( flags & HVMCOPY_to_guest )
        {
            if ( p2m_is_discard_write(p2mt) )
            {
                static unsigned long lastpage;

                if ( xchg(&lastpage, gfn_x(gfn)) != gfn_x(gfn) )
                    dprintk(XENLOG_G_DEBUG,
                            "%pv attempted write to read-only gfn %#lx (mfn=%#"PRI_mfn")\n",
                            v, gfn_x(gfn), mfn_x(page_to_mfn(page)));
            }
            else
            {
                if ( buf )
                    memcpy(p, buf, count);
                else
                    memset(p, 0, count);
                paging_mark_pfn_dirty(v->domain, _pfn(gfn_x(gfn)));
            }
        }
        else
        {
            memcpy(buf, p, count);
        }

        unmap_domain_page(p);

        addr += count;
        if ( buf )
            buf += count;
        todo -= count;
        put_page(page);
    }

    return HVMTRANS_okay;
}

enum hvm_translation_result hvm_copy_to_guest_phys(
    paddr_t paddr, void *buf, int size, struct vcpu *v)
{
    return __hvm_copy(buf, paddr, size, v,
                      HVMCOPY_to_guest | HVMCOPY_phys, 0, NULL);
}

enum hvm_translation_result hvm_copy_from_guest_phys(
    void *buf, paddr_t paddr, int size)
{
    return __hvm_copy(buf, paddr, size, current,
                      HVMCOPY_from_guest | HVMCOPY_phys, 0, NULL);
}

enum hvm_translation_result hvm_copy_to_guest_linear(
    unsigned long addr, void *buf, int size, uint32_t pfec,
    pagefault_info_t *pfinfo)
{
    return __hvm_copy(buf, addr, size, current,
                      HVMCOPY_to_guest | HVMCOPY_linear,
                      PFEC_page_present | PFEC_write_access | pfec, pfinfo);
}

enum hvm_translation_result hvm_copy_from_guest_linear(
    void *buf, unsigned long addr, int size, uint32_t pfec,
    pagefault_info_t *pfinfo)
{
    return __hvm_copy(buf, addr, size, current,
                      HVMCOPY_from_guest | HVMCOPY_linear,
                      PFEC_page_present | pfec, pfinfo);
}

unsigned long copy_to_user_hvm(void *to, const void *from, unsigned int len)
{
    int rc;

    if ( current->hcall_compat && is_compat_arg_xlat_range(to, len) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_to_guest_linear((unsigned long)to, (void *)from, len, 0, NULL);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long clear_user_hvm(void *to, unsigned int len)
{
    int rc;

    if ( current->hcall_compat && is_compat_arg_xlat_range(to, len) )
    {
        memset(to, 0x00, len);
        return 0;
    }

    rc = hvm_copy_to_guest_linear((unsigned long)to, NULL, len, 0, NULL);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len)
{
    int rc;

    if ( current->hcall_compat && is_compat_arg_xlat_range(from, len) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_from_guest_linear(to, (unsigned long)from, len, 0, NULL);
    return rc ? len : 0; /* fake a copy_from_user() return code */
}

bool hvm_check_cpuid_faulting(struct vcpu *v)
{
    const struct vcpu_msrs *msrs = v->arch.msrs;

    if ( !msrs->misc_features_enables.cpuid_faulting )
        return false;

    return hvm_get_cpl(v) > 0;
}

static uint64_t _hvm_rdtsc_intercept(void)
{
    struct vcpu *curr = current;
#if !defined(NDEBUG) || defined(CONFIG_PERF_COUNTERS)
    struct domain *currd = curr->domain;

    if ( currd->arch.vtsc )
        switch ( hvm_guest_x86_mode(curr) )
        {
        case 8:
        case 4:
        case 2:
            if ( unlikely(hvm_get_cpl(curr)) )
            {
        case 1:
                currd->arch.vtsc_usercount++;
                break;
            }
            /* fall through */
        case 0:
            currd->arch.vtsc_kerncount++;
            break;
        }
#endif

    return hvm_get_guest_tsc(curr);
}

void hvm_rdtsc_intercept(struct cpu_user_regs *regs)
{
    msr_split(regs, _hvm_rdtsc_intercept());

    HVMTRACE_2D(RDTSC, regs->eax, regs->edx);
}

int hvm_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    uint64_t *var_range_base, *fixed_range_base;
    int ret;

    var_range_base = (uint64_t *)v->arch.hvm.mtrr.var_ranges;
    fixed_range_base = (uint64_t *)v->arch.hvm.mtrr.fixed_ranges;

    if ( (ret = guest_rdmsr(v, msr, msr_content)) != X86EMUL_UNHANDLEABLE )
        return ret;

    ret = X86EMUL_OKAY;

    switch ( msr )
    {
        unsigned int index;

    case MSR_EFER:
        *msr_content = v->arch.hvm.guest_efer;
        break;

    case MSR_IA32_TSC:
        *msr_content = _hvm_rdtsc_intercept();
        break;

    case MSR_IA32_TSC_ADJUST:
        *msr_content = v->arch.hvm.msr_tsc_adjust;
        break;

    case MSR_APIC_BASE:
        *msr_content = vcpu_vlapic(v)->hw.apic_base_msr;
        break;

    case MSR_IA32_TSC_DEADLINE:
        *msr_content = vlapic_tdt_msr_get(vcpu_vlapic(v));
        break;

    case MSR_IA32_CR_PAT:
        hvm_get_guest_pat(v, msr_content);
        break;

    case MSR_MTRRcap:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        *msr_content = v->arch.hvm.mtrr.mtrr_cap;
        break;
    case MSR_MTRRdefType:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        *msr_content = v->arch.hvm.mtrr.def_type |
                       MASK_INSR(v->arch.hvm.mtrr.enabled, MTRRdefType_E) |
                       MASK_INSR(v->arch.hvm.mtrr.fixed_enabled,
                                 MTRRdefType_FE);
        break;
    case MSR_MTRRfix64K_00000:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        *msr_content = fixed_range_base[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix16K_80000;
        *msr_content = fixed_range_base[array_index_nospec(index + 1,
                                   ARRAY_SIZE(v->arch.hvm.mtrr.fixed_ranges))];
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix4K_C0000;
        *msr_content = fixed_range_base[array_index_nospec(index + 3,
                                   ARRAY_SIZE(v->arch.hvm.mtrr.fixed_ranges))];
        break;
    case MSR_IA32_MTRR_PHYSBASE(0)...MSR_IA32_MTRR_PHYSMASK(MTRR_VCNT_MAX - 1):
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        index = msr - MSR_IA32_MTRR_PHYSBASE(0);
        if ( (index / 2) >=
             MASK_EXTR(v->arch.hvm.mtrr.mtrr_cap, MTRRcap_VCNT) )
            goto gp_fault;
        *msr_content = var_range_base[array_index_nospec(index,
                                      2 * MASK_EXTR(v->arch.hvm.mtrr.mtrr_cap,
                                                    MTRRcap_VCNT))];
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
               ? alternative_call(hvm_funcs.msr_read_intercept,
                                  msr, msr_content)
               : X86EMUL_OKAY);
        break;
    }

 out:
    HVMTRACE_3D(MSR_READ, msr,
                (uint32_t)*msr_content, (uint32_t)(*msr_content >> 32));
    return ret;

 gp_fault:
    ret = X86EMUL_EXCEPTION;
    *msr_content = -1ull;
    goto out;
}

int hvm_msr_write_intercept(unsigned int msr, uint64_t msr_content,
                            bool may_defer)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    int ret;

    HVMTRACE_3D(MSR_WRITE, msr,
               (uint32_t)msr_content, (uint32_t)(msr_content >> 32));

    if ( may_defer && unlikely(monitored_msr(v->domain, msr)) )
    {
        uint64_t msr_old_content;

        ret = hvm_msr_read_intercept(msr, &msr_old_content);
        if ( ret != X86EMUL_OKAY )
            return ret;

        ASSERT(v->arch.vm_event);

        /* The actual write will occur in hvm_do_resume() (if permitted). */
        v->arch.vm_event->write_data.do_write.msr = 1;
        v->arch.vm_event->write_data.msr = msr;
        v->arch.vm_event->write_data.value = msr_content;

        hvm_monitor_msr(msr, msr_content, msr_old_content);
        return X86EMUL_OKAY;
    }

    if ( (ret = guest_wrmsr(v, msr, msr_content)) != X86EMUL_UNHANDLEABLE )
        return ret;

    ret = X86EMUL_OKAY;

    switch ( msr )
    {
        unsigned int index;

    case MSR_EFER:
        if ( hvm_set_efer(msr_content) )
           return X86EMUL_EXCEPTION;
        break;

    case MSR_IA32_TSC:
        hvm_set_guest_tsc_msr(v, msr_content);
        break;

    case MSR_IA32_TSC_ADJUST:
        hvm_set_guest_tsc_adjust(v, msr_content);
        break;

    case MSR_APIC_BASE:
        return guest_wrmsr_apic_base(v, msr_content);

    case MSR_IA32_TSC_DEADLINE:
        vlapic_tdt_msr_set(vcpu_vlapic(v), msr_content);
        break;

    case MSR_IA32_CR_PAT:
        if ( !hvm_set_guest_pat(v, msr_content) )
           goto gp_fault;
        break;

    case MSR_MTRRcap:
        goto gp_fault;

    case MSR_MTRRdefType:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        if ( !mtrr_def_type_msr_set(v->domain, &v->arch.hvm.mtrr,
                                    msr_content) )
           goto gp_fault;
        break;
    case MSR_MTRRfix64K_00000:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        if ( !mtrr_fix_range_msr_set(v->domain, &v->arch.hvm.mtrr, 0,
                                     msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix16K_80000 + 1;
        if ( !mtrr_fix_range_msr_set(v->domain, &v->arch.hvm.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix4K_C0000 + 3;
        if ( !mtrr_fix_range_msr_set(v->domain, &v->arch.hvm.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_IA32_MTRR_PHYSBASE(0)...MSR_IA32_MTRR_PHYSMASK(MTRR_VCNT_MAX - 1):
        if ( !d->arch.cpuid->basic.mtrr )
            goto gp_fault;
        index = msr - MSR_IA32_MTRR_PHYSBASE(0);
        if ( ((index / 2) >=
              MASK_EXTR(v->arch.hvm.mtrr.mtrr_cap, MTRRcap_VCNT)) ||
             !mtrr_var_range_msr_set(v->domain, &v->arch.hvm.mtrr,
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
               ? alternative_call(hvm_funcs.msr_write_intercept,
                                  msr, msr_content)
               : X86EMUL_OKAY);
        break;
    }

    return ret;

gp_fault:
    return X86EMUL_EXCEPTION;
}

static bool is_sysdesc_access(const struct x86_emulate_state *state,
                              const struct x86_emulate_ctxt *ctxt)
{
    unsigned int ext;
    int mode = x86_insn_modrm(state, NULL, &ext);

    switch ( ctxt->opcode )
    {
    case X86EMUL_OPC(0x0f, 0x00):
        if ( !(ext & 4) ) /* SLDT / STR / LLDT / LTR */
            return true;
        break;

    case X86EMUL_OPC(0x0f, 0x01):
        if ( mode != 3 && !(ext & 4) ) /* SGDT / SIDT / LGDT / LIDT */
            return true;
        break;
    }

    return false;
}

int hvm_descriptor_access_intercept(uint64_t exit_info,
                                    uint64_t vmx_exit_qualification,
                                    unsigned int descriptor, bool is_write)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;

    if ( currd->arch.monitor.descriptor_access_enabled )
    {
        ASSERT(curr->arch.vm_event);
        hvm_monitor_descriptor_access(exit_info, vmx_exit_qualification,
                                      descriptor, is_write);
    }
    else if ( !hvm_emulate_one_insn(is_sysdesc_access, "sysdesc access") )
        domain_crash(currd);

    return X86EMUL_OKAY;
}

static bool is_cross_vendor(const struct x86_emulate_state *state,
                            const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
    case X86EMUL_OPC(0x0f, 0x05): /* syscall */
    case X86EMUL_OPC(0x0f, 0x34): /* sysenter */
    case X86EMUL_OPC(0x0f, 0x35): /* sysexit */
        return true;
    }

    return false;
}

void hvm_ud_intercept(struct cpu_user_regs *regs)
{
    struct vcpu *cur = current;
    bool should_emulate =
        cur->domain->arch.cpuid->x86_vendor != boot_cpu_data.x86_vendor;
    struct hvm_emulate_ctxt ctxt;

    hvm_emulate_init_once(&ctxt, opt_hvm_fep ? NULL : is_cross_vendor, regs);

    if ( opt_hvm_fep )
    {
        const struct segment_register *cs = &ctxt.seg_reg[x86_seg_cs];
        uint32_t walk = ((ctxt.seg_reg[x86_seg_ss].dpl == 3)
                         ? PFEC_user_mode : 0) | PFEC_insn_fetch;
        unsigned long addr;
        char sig[5]; /* ud2; .ascii "xen" */

        if ( hvm_virtual_to_linear_addr(x86_seg_cs, cs, regs->rip,
                                        sizeof(sig), hvm_access_insn_fetch,
                                        cs, &addr) &&
             (hvm_copy_from_guest_linear(sig, addr, sizeof(sig),
                                         walk, NULL) == HVMTRANS_okay) &&
             (memcmp(sig, "\xf\xbxen", sizeof(sig)) == 0) )
        {
            regs->rip += sizeof(sig);
            regs->eflags &= ~X86_EFLAGS_RF;

            /* Zero the upper 32 bits of %rip if not in 64bit mode. */
            if ( !(hvm_long_mode_active(cur) && cs->l) )
                regs->rip = regs->eip;

            add_taint(TAINT_HVM_FEP);

            should_emulate = true;
        }
    }

    if ( !should_emulate )
    {
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        return;
    }

    switch ( hvm_emulate_one(&ctxt) )
    {
    case X86EMUL_UNHANDLEABLE:
    case X86EMUL_UNIMPLEMENTED:
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        break;
    case X86EMUL_EXCEPTION:
        hvm_inject_event(&ctxt.ctxt.event);
        /* fall through */
    default:
        hvm_emulate_writeback(&ctxt);
        break;
    }
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
    alternative_vcall(hvm_funcs.init_hypercall_page, d, hypercall_page);
}

void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip)
{
    struct domain *d = v->domain;
    struct segment_register reg;

    domain_lock(d);

    if ( v->is_initialised )
        goto out;

    if ( !paging_mode_hap(d) )
    {
        if ( v->arch.hvm.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_null();
    }

    if ( v->arch.xsave_area )
        v->arch.xsave_area->xsave_hdr.xstate_bv = 0;
    vcpu_setup_fpu(v, v->arch.xsave_area, NULL, FCW_RESET);

    v->arch.vgc_flags = VGCF_online;

    arch_vcpu_regs_init(v);
    v->arch.user_regs.rip = ip;

    v->arch.hvm.guest_cr[0] = X86_CR0_ET;
    hvm_update_guest_cr(v, 0);

    v->arch.hvm.guest_cr[2] = 0;
    hvm_update_guest_cr(v, 2);

    v->arch.hvm.guest_cr[3] = 0;
    hvm_update_guest_cr(v, 3);

    v->arch.hvm.guest_cr[4] = 0;
    hvm_update_guest_cr(v, 4);

    v->arch.hvm.guest_efer = 0;
    hvm_update_guest_efer(v);

    reg.sel = cs;
    reg.base = (uint32_t)reg.sel << 4;
    reg.limit = 0xffff;
    reg.attr = 0x9b;
    hvm_set_segment_register(v, x86_seg_cs, &reg);

    reg.sel = reg.base = 0;
    reg.limit = 0xffff;
    reg.attr = 0x93;
    hvm_set_segment_register(v, x86_seg_ds, &reg);
    hvm_set_segment_register(v, x86_seg_es, &reg);
    hvm_set_segment_register(v, x86_seg_fs, &reg);
    hvm_set_segment_register(v, x86_seg_gs, &reg);
    hvm_set_segment_register(v, x86_seg_ss, &reg);

    reg.attr = 0x82; /* LDT */
    hvm_set_segment_register(v, x86_seg_ldtr, &reg);

    reg.attr = 0x8b; /* 32-bit TSS (busy) */
    hvm_set_segment_register(v, x86_seg_tr, &reg);

    reg.attr = 0;
    hvm_set_segment_register(v, x86_seg_gdtr, &reg);
    hvm_set_segment_register(v, x86_seg_idtr, &reg);

    if ( hvm_funcs.tsc_scaling.setup )
        hvm_funcs.tsc_scaling.setup(v);

    /* Sync AP's TSC with BSP's. */
    v->arch.hvm.cache_tsc_offset =
        v->domain->vcpu[0]->arch.hvm.cache_tsc_offset;
    hvm_set_tsc_offset(v, v->arch.hvm.cache_tsc_offset,
                       d->arch.hvm.sync_tsc);

    v->arch.hvm.msr_tsc_adjust = 0;

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
         test_and_set_bool(d->arch.hvm.is_s3_suspended) )
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
    if ( test_and_clear_bool(d->arch.hvm.is_s3_suspended) )
    {
        struct vcpu *v;

        for_each_vcpu( d, v )
            hvm_set_guest_tsc(v, 0);
        domain_unpause(d);
    }
}

bool hvm_flush_vcpu_tlb(bool (*flush_vcpu)(void *ctxt, struct vcpu *v),
                        void *ctxt)
{
    static DEFINE_PER_CPU(cpumask_t, flush_cpumask);
    cpumask_t *mask = &this_cpu(flush_cpumask);
    struct domain *d = current->domain;
    struct vcpu *v;

    /* Avoid deadlock if more than one vcpu tries this at the same time. */
    if ( !spin_trylock(&d->hypercall_deadlock_mutex) )
        return false;

    /* Pause all other vcpus. */
    for_each_vcpu ( d, v )
        if ( v != current && flush_vcpu(ctxt, v) )
            vcpu_pause_nosync(v);

    /* Now that all VCPUs are signalled to deschedule, we wait... */
    for_each_vcpu ( d, v )
        if ( v != current && flush_vcpu(ctxt, v) )
            while ( !vcpu_runnable(v) && v->is_running )
                cpu_relax();

    /* All other vcpus are paused, safe to unlock now. */
    spin_unlock(&d->hypercall_deadlock_mutex);

    cpumask_clear(mask);

    /* Flush paging-mode soft state (e.g., va->gfn cache; PAE PDPE cache). */
    for_each_vcpu ( d, v )
    {
        unsigned int cpu;

        if ( !flush_vcpu(ctxt, v) )
            continue;

        paging_update_cr3(v, false);

        cpu = read_atomic(&v->dirty_cpu);
        if ( is_vcpu_dirty_cpu(cpu) )
            __cpumask_set_cpu(cpu, mask);
    }

    /* Flush TLBs on all CPUs with dirty vcpu state. */
    flush_tlb_mask(mask);

    /* Done. */
    for_each_vcpu ( d, v )
        if ( v != current && flush_vcpu(ctxt, v) )
            vcpu_unpause(v);

    return true;
}

static bool always_flush(void *ctxt, struct vcpu *v)
{
    return true;
}

static int hvmop_flush_tlb_all(void)
{
    if ( !is_hvm_domain(current->domain) )
        return -EINVAL;

    return hvm_flush_vcpu_tlb(always_flush, NULL) ? 0 : -ERESTART;
}

static int hvmop_set_evtchn_upcall_vector(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_evtchn_upcall_vector_t) uop)
{
    xen_hvm_evtchn_upcall_vector_t op;
    struct domain *d = current->domain;
    struct vcpu *v;

    if ( !is_hvm_domain(d) )
        return -EINVAL;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( op.vector < 0x10 )
        return -EINVAL;

    if ( (v = domain_vcpu(d, op.vcpu)) == NULL )
        return -ENOENT;

    printk(XENLOG_G_INFO "%pv: upcall vector %02x\n", v, op.vector);

    v->arch.hvm.evtchn_upcall_vector = op.vector;
    hvm_assert_evtchn_irq(v);
    return 0;
}

static int hvm_allow_set_param(struct domain *d,
                               const struct xen_hvm_param *a)
{
    uint64_t value = d->arch.hvm.params[a->index];
    int rc;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_set_param);
    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters can be set by the guest. */
    case HVM_PARAM_CALLBACK_IRQ:
    case HVM_PARAM_VM86_TSS:
    case HVM_PARAM_VM86_TSS_SIZED:
    case HVM_PARAM_ACPI_IOPORTS_LOCATION:
    case HVM_PARAM_VM_GENERATION_ID_ADDR:
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_EVTCHN:
    case HVM_PARAM_X87_FIP_WIDTH:
        break;
    /* The following parameters are deprecated. */
    case HVM_PARAM_DM_DOMAIN:
    case HVM_PARAM_BUFIOREQ_EVTCHN:
        rc = -EPERM;
        break;
    /*
     * The following parameters must not be set by the guest
     * since the domain may need to be paused.
     */
    case HVM_PARAM_IDENT_PT:
    case HVM_PARAM_ACPI_S_STATE:
    /* The remaining parameters should not be set by the guest. */
    default:
        if ( d == current->domain )
            rc = -EPERM;
        break;
    }

    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters should only be changed once. */
    case HVM_PARAM_VIRIDIAN:
    case HVM_PARAM_IOREQ_PFN:
    case HVM_PARAM_BUFIOREQ_PFN:
    case HVM_PARAM_IOREQ_SERVER_PFN:
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
    case HVM_PARAM_ALTP2M:
    case HVM_PARAM_MCA_CAP:
        if ( value != 0 && a->value != value )
            rc = -EEXIST;
        break;
    default:
        break;
    }

    return rc;
}

static int hvmop_set_param(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_param_t) arg)
{
    struct domain *curr_d = current->domain;
    struct xen_hvm_param a;
    struct domain *d;
    struct vcpu *v;
    int rc;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.index >= HVM_NR_PARAMS )
        return -EINVAL;

    /* Make sure the above bound check is not bypassed during speculation. */
    block_speculation();

    d = rcu_lock_domain_by_any_id(a.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = hvm_allow_set_param(d, &a);
    if ( rc )
        goto out;

    switch ( a.index )
    {
    case HVM_PARAM_CALLBACK_IRQ:
        hvm_set_callback_via(d, a.value);
        hvm_latch_shinfo_size(d);
        break;
    case HVM_PARAM_TIMER_MODE:
        if ( a.value > HVMPTM_one_missed_tick_pending )
            rc = -EINVAL;
        break;
    case HVM_PARAM_VIRIDIAN:
        if ( (a.value & ~HVMPV_feature_mask) ||
             !(a.value & HVMPV_base_freq) )
            rc = -EINVAL;
        break;
    case HVM_PARAM_IDENT_PT:
        /*
         * Only actually required for VT-x lacking unrestricted_guest
         * capabilities.  Short circuit the pause if possible.
         */
        if ( !paging_mode_hap(d) || !cpu_has_vmx )
        {
            d->arch.hvm.params[a.index] = a.value;
            break;
        }

        /*
         * Update GUEST_CR3 in each VMCS to point at identity map.
         * All foreign updates to guest state must synchronise on
         * the domctl_lock.
         */
        rc = -ERESTART;
        if ( !domctl_lock_acquire() )
            break;

        rc = 0;
        domain_pause(d);
        d->arch.hvm.params[a.index] = a.value;
        for_each_vcpu ( d, v )
            paging_update_cr3(v, false);
        domain_unpause(d);

        domctl_lock_release();
        break;
    case HVM_PARAM_DM_DOMAIN:
        /* The only value this should ever be set to is DOMID_SELF */
        if ( a.value != DOMID_SELF )
            rc = -EINVAL;

        a.value = curr_d->domain_id;
        break;
    case HVM_PARAM_ACPI_S_STATE:
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
    case HVM_PARAM_MEMORY_EVENT_INT3:
    case HVM_PARAM_MEMORY_EVENT_SINGLE_STEP:
    case HVM_PARAM_MEMORY_EVENT_MSR:
        /* Deprecated */
        rc = -EOPNOTSUPP;
        break;
    case HVM_PARAM_NESTEDHVM:
        rc = xsm_hvm_param_nested(XSM_PRIV, d);
        if ( rc )
            break;
        if ( a.value > 1 )
            rc = -EINVAL;
        /*
         * Remove the check below once we have
         * shadow-on-shadow.
         */
        if ( !paging_mode_hap(d) && a.value )
            rc = -EINVAL;
        if ( a.value &&
             d->arch.hvm.params[HVM_PARAM_ALTP2M] )
            rc = -EINVAL;
        /* Set up NHVM state for any vcpus that are already up. */
        if ( a.value &&
             !d->arch.hvm.params[HVM_PARAM_NESTEDHVM] )
            for_each_vcpu(d, v)
                if ( rc == 0 )
                    rc = nestedhvm_vcpu_initialise(v);
        if ( !a.value || rc )
            for_each_vcpu(d, v)
                nestedhvm_vcpu_destroy(v);
        break;
    case HVM_PARAM_ALTP2M:
        rc = xsm_hvm_param_altp2mhvm(XSM_PRIV, d);
        if ( rc )
            break;
        if ( a.value > XEN_ALTP2M_limited )
            rc = -EINVAL;
        if ( a.value &&
             d->arch.hvm.params[HVM_PARAM_NESTEDHVM] )
            rc = -EINVAL;
        break;
    case HVM_PARAM_TRIPLE_FAULT_REASON:
        if ( a.value > SHUTDOWN_MAX )
            rc = -EINVAL;
        break;
    case HVM_PARAM_IOREQ_SERVER_PFN:
        d->arch.hvm.ioreq_gfn.base = a.value;
        break;
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
    {
        unsigned int i;

        if ( a.value == 0 ||
             a.value > sizeof(d->arch.hvm.ioreq_gfn.mask) * 8 )
        {
            rc = -EINVAL;
            break;
        }
        for ( i = 0; i < a.value; i++ )
            set_bit(i, &d->arch.hvm.ioreq_gfn.mask);

        break;
    }

    case HVM_PARAM_IOREQ_PFN:
    case HVM_PARAM_BUFIOREQ_PFN:
        BUILD_BUG_ON(HVM_PARAM_IOREQ_PFN >
                     sizeof(d->arch.hvm.ioreq_gfn.legacy_mask) * 8);
        BUILD_BUG_ON(HVM_PARAM_BUFIOREQ_PFN >
                     sizeof(d->arch.hvm.ioreq_gfn.legacy_mask) * 8);
        if ( a.value )
            set_bit(a.index, &d->arch.hvm.ioreq_gfn.legacy_mask);
        break;

    case HVM_PARAM_X87_FIP_WIDTH:
        if ( a.value != 0 && a.value != 4 && a.value != 8 )
        {
            rc = -EINVAL;
            break;
        }
        d->arch.x87_fip_width = a.value;
        break;

    case HVM_PARAM_VM86_TSS:
        /* Hardware would silently truncate high bits. */
        if ( a.value != (uint32_t)a.value )
        {
            if ( d == curr_d )
                domain_crash(d);
            rc = -EINVAL;
        }
        /* Old hvmloader binaries hardcode the size to 128 bytes. */
        if ( a.value )
            a.value |= (128ULL << 32) | VM86_TSS_UPDATED;
        a.index = HVM_PARAM_VM86_TSS_SIZED;
        break;

    case HVM_PARAM_VM86_TSS_SIZED:
        if ( (a.value >> 32) < sizeof(struct tss32) )
        {
            if ( d == curr_d )
                domain_crash(d);
            rc = -EINVAL;
        }
        /*
         * Cap at the theoretically useful maximum (base structure plus
         * 256 bits interrupt redirection bitmap + 64k bits I/O bitmap
         * plus one padding byte).
         */
        if ( (a.value >> 32) > sizeof(struct tss32) +
                               (0x100 / 8) + (0x10000 / 8) + 1 )
            a.value = (uint32_t)a.value |
                      ((sizeof(struct tss32) + (0x100 / 8) +
                                               (0x10000 / 8) + 1) << 32);
        a.value |= VM86_TSS_UPDATED;
        break;

    case HVM_PARAM_MCA_CAP:
        rc = vmce_enable_mca_cap(d, a.value);
        break;
    }

    if ( rc != 0 )
        goto out;

    d->arch.hvm.params[a.index] = a.value;

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "set param %u = %"PRIx64,
                a.index, a.value);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvm_allow_get_param(struct domain *d,
                               const struct xen_hvm_param *a)
{
    int rc;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_get_param);
    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters can be read by the guest. */
    case HVM_PARAM_CALLBACK_IRQ:
    case HVM_PARAM_VM86_TSS:
    case HVM_PARAM_VM86_TSS_SIZED:
    case HVM_PARAM_ACPI_IOPORTS_LOCATION:
    case HVM_PARAM_VM_GENERATION_ID_ADDR:
    case HVM_PARAM_STORE_PFN:
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_PFN:
    case HVM_PARAM_CONSOLE_EVTCHN:
    case HVM_PARAM_ALTP2M:
    case HVM_PARAM_X87_FIP_WIDTH:
        break;
    /* The following parameters are deprecated. */
    case HVM_PARAM_DM_DOMAIN:
    case HVM_PARAM_BUFIOREQ_EVTCHN:
        rc = -ENODATA;
        break;
    /* The remaining parameters should not be read by the guest. */
    default:
        if ( d == current->domain )
            rc = -EPERM;
        break;
    }

    return rc;
}

static int hvmop_get_param(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_param_t) arg)
{
    struct xen_hvm_param a;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.index >= HVM_NR_PARAMS )
        return -EINVAL;

    /* Make sure the above bound check is not bypassed during speculation. */
    block_speculation();

    d = rcu_lock_domain_by_any_id(a.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = hvm_allow_get_param(d, &a);
    if ( rc )
        goto out;

    switch ( a.index )
    {
    case HVM_PARAM_ACPI_S_STATE:
        a.value = d->arch.hvm.is_s3_suspended ? 3 : 0;
        break;

    case HVM_PARAM_VM86_TSS:
        a.value = (uint32_t)d->arch.hvm.params[HVM_PARAM_VM86_TSS_SIZED];
        break;

    case HVM_PARAM_VM86_TSS_SIZED:
        a.value = d->arch.hvm.params[HVM_PARAM_VM86_TSS_SIZED] &
                  ~VM86_TSS_UPDATED;
        break;

    case HVM_PARAM_X87_FIP_WIDTH:
        a.value = d->arch.x87_fip_width;
        break;
    default:
        a.value = d->arch.hvm.params[a.index];
        break;
    }

    rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "get param %u = %"PRIx64,
                a.index, a.value);

 out:
    rcu_unlock_domain(d);
    return rc;
}

/*
 * altp2m operations are envisioned as being used in several different
 * modes:
 *
 * - external: All control and decisions are made by an external agent
 *   running domain 0.
 *
 * - internal: altp2m operations are used exclusively by an in-guest
 *   agent to protect itself from the guest kernel and in-guest
 *   attackers.
 *
 * - coordinated: An in-guest agent handles #VE and VMFUNCs locally,
 *   but makes requests of an agent running outside the domain for
 *   bigger changes (such as modifying altp2m entires).
 *
 * This corresponds to the three values for HVM_PARAM_ALTP2M
 * (external, mixed, limited). All three models have advantages and
 * disadvantages.
 *
 * Normally hypercalls made by a program in domain 0 in order to
 * control a guest would be DOMCTLs rather than HVMOPs.  But in order
 * to properly enable the 'internal' use case, as well as to avoid
 * fragmentation, all altp2m subops should come under this single
 * HVMOP.
 *
 * Note that 'internal' mode (HVM_PARAM_ALTP2M == XEN_ALTP2M_mixed)
 * has not been evaluated for safety from a security perspective.
 * Before using this mode in a security-critical environment, each
 * subop should be evaluated for safety, with unsafe subops
 * blacklisted in xsm_hvm_altp2mhvm_op().
 */
static int do_altp2m_op(
    XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xen_hvm_altp2m_op a;
    struct domain *d = NULL;
    int rc = 0;
    uint64_t mode;

    if ( !hvm_altp2m_supported() )
        return -EOPNOTSUPP;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.pad1 || a.pad2 ||
         (a.version != HVMOP_ALTP2M_INTERFACE_VERSION) )
        return -EINVAL;

    switch ( a.cmd )
    {
    case HVMOP_altp2m_get_domain_state:
    case HVMOP_altp2m_set_domain_state:
    case HVMOP_altp2m_vcpu_enable_notify:
    case HVMOP_altp2m_vcpu_disable_notify:
    case HVMOP_altp2m_create_p2m:
    case HVMOP_altp2m_destroy_p2m:
    case HVMOP_altp2m_switch_p2m:
    case HVMOP_altp2m_set_suppress_ve:
    case HVMOP_altp2m_get_suppress_ve:
    case HVMOP_altp2m_set_mem_access:
    case HVMOP_altp2m_set_mem_access_multi:
    case HVMOP_altp2m_get_mem_access:
    case HVMOP_altp2m_change_gfn:
        break;

    default:
        return -EOPNOTSUPP;
    }

    d = rcu_lock_domain_by_any_id(a.domain);

    if ( d == NULL )
        return -ESRCH;

    if ( !is_hvm_domain(d) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    if ( (a.cmd != HVMOP_altp2m_get_domain_state) &&
         (a.cmd != HVMOP_altp2m_set_domain_state) &&
         !d->arch.altp2m_active )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    mode = d->arch.hvm.params[HVM_PARAM_ALTP2M];

    if ( XEN_ALTP2M_disabled == mode )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( (rc = xsm_hvm_altp2mhvm_op(XSM_OTHER, d, mode, a.cmd)) )
        goto out;

    switch ( a.cmd )
    {
    case HVMOP_altp2m_get_domain_state:
        a.u.domain_state.state = altp2m_active(d);
        rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        break;

    case HVMOP_altp2m_set_domain_state:
    {
        struct vcpu *v;
        bool_t ostate;

        if ( nestedhvm_enabled(d) )
        {
            rc = -EINVAL;
            break;
        }

        rc = domain_pause_except_self(d);
        if ( rc )
            break;

        ostate = d->arch.altp2m_active;
        d->arch.altp2m_active = !!a.u.domain_state.state;

        /* If the alternate p2m state has changed, handle appropriately */
        if ( d->arch.altp2m_active != ostate &&
             (ostate || !(rc = p2m_init_altp2m_by_id(d, 0))) )
        {
            for_each_vcpu( d, v )
            {
                if ( !ostate )
                    altp2m_vcpu_initialise(v);
                else
                    altp2m_vcpu_destroy(v);
            }

            if ( ostate )
                p2m_flush_altp2m(d);
        }

        domain_unpause_except_self(d);
        break;
    }

    case HVMOP_altp2m_vcpu_enable_notify:
    {
        struct vcpu *v;

        if ( a.u.enable_notify.pad ||
             a.u.enable_notify.vcpu_id >= d->max_vcpus )
        {
            rc = -EINVAL;
            break;
        }

        if ( !cpu_has_vmx_virt_exceptions )
        {
            rc = -EOPNOTSUPP;
            break;
        }

        v = d->vcpu[a.u.enable_notify.vcpu_id];

        rc = altp2m_vcpu_enable_ve(v, _gfn(a.u.enable_notify.gfn));
        break;
    }

    case HVMOP_altp2m_vcpu_disable_notify:
    {
        struct vcpu *v;

        if ( a.u.disable_notify.vcpu_id >= d->max_vcpus )
        {
            rc = -EINVAL;
            break;
        }

        if ( !cpu_has_vmx_virt_exceptions )
        {
            rc = -EOPNOTSUPP;
            break;
        }

        v = d->vcpu[a.u.enable_notify.vcpu_id];

        altp2m_vcpu_disable_ve(v);
        break;
    }

    case HVMOP_altp2m_create_p2m:
        if ( !(rc = p2m_init_next_altp2m(d, &a.u.view.view)) )
            rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        break;

    case HVMOP_altp2m_destroy_p2m:
        rc = p2m_destroy_altp2m_by_id(d, a.u.view.view);
        break;

    case HVMOP_altp2m_switch_p2m:
        rc = p2m_switch_domain_altp2m_by_id(d, a.u.view.view);
        break;

    case HVMOP_altp2m_set_suppress_ve:
        if ( a.u.suppress_ve.pad1 || a.u.suppress_ve.pad2 )
            rc = -EINVAL;
        else
        {
            gfn_t gfn = _gfn(a.u.mem_access.gfn);
            unsigned int altp2m_idx = a.u.mem_access.view;
            bool suppress_ve = a.u.suppress_ve.suppress_ve;

            rc = p2m_set_suppress_ve(d, gfn, suppress_ve, altp2m_idx);
        }
        break;

    case HVMOP_altp2m_get_suppress_ve:
        if ( a.u.suppress_ve.pad1 || a.u.suppress_ve.pad2 )
            rc = -EINVAL;
        else
        {
            gfn_t gfn = _gfn(a.u.suppress_ve.gfn);
            unsigned int altp2m_idx = a.u.suppress_ve.view;
            bool suppress_ve;

            rc = p2m_get_suppress_ve(d, gfn, &suppress_ve, altp2m_idx);
            if ( !rc )
            {
                a.u.suppress_ve.suppress_ve = suppress_ve;
                rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
            }
        }
        break;

    case HVMOP_altp2m_set_mem_access:
        if ( a.u.mem_access.pad )
            rc = -EINVAL;
        else
            rc = p2m_set_mem_access(d, _gfn(a.u.mem_access.gfn), 1, 0, 0,
                                    a.u.mem_access.access,
                                    a.u.mem_access.view);
        break;

    case HVMOP_altp2m_set_mem_access_multi:
        if ( a.u.set_mem_access_multi.pad ||
             a.u.set_mem_access_multi.opaque > a.u.set_mem_access_multi.nr )
        {
            rc = -EINVAL;
            break;
        }

        /*
         * Unlike XENMEM_access_op_set_access_multi, we don't need any bits of
         * the 'continuation' counter to be zero (to stash a command in).
         * However, 0x40 is a good 'stride' to make sure that we make
         * a reasonable amount of forward progress before yielding,
         * so use a mask of 0x3F here.
         */
        rc = p2m_set_mem_access_multi(d, a.u.set_mem_access_multi.pfn_list,
                                      a.u.set_mem_access_multi.access_list,
                                      a.u.set_mem_access_multi.nr,
                                      a.u.set_mem_access_multi.opaque,
                                      0x3F,
                                      a.u.set_mem_access_multi.view);
        if ( rc > 0 )
        {
            a.u.set_mem_access_multi.opaque = rc;
            rc = -ERESTART;
            if ( __copy_field_to_guest(guest_handle_cast(arg, xen_hvm_altp2m_op_t),
                                       &a, u.set_mem_access_multi.opaque) )
                rc = -EFAULT;
        }
        break;

    case HVMOP_altp2m_get_mem_access:
        if ( a.u.mem_access.pad )
            rc = -EINVAL;
        else
        {
            xenmem_access_t access;

            rc = p2m_get_mem_access(d, _gfn(a.u.mem_access.gfn), &access,
                                    a.u.mem_access.view);
            if ( !rc )
            {
                a.u.mem_access.access = access;
                rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
            }
        }
        break;

    case HVMOP_altp2m_change_gfn:
        if ( a.u.change_gfn.pad1 || a.u.change_gfn.pad2 )
            rc = -EINVAL;
        else
            rc = p2m_change_altp2m_gfn(d, a.u.change_gfn.view,
                    _gfn(a.u.change_gfn.old_gfn),
                    _gfn(a.u.change_gfn.new_gfn));
        break;
    default:
        ASSERT_UNREACHABLE();
    }

 out:
    rcu_unlock_domain(d);

    return rc;
}

DEFINE_XEN_GUEST_HANDLE(compat_hvm_altp2m_op_t);

/*
 * Manually define the CHECK_ macros for hvm_altp2m_op and
 * hvm_altp2m_set_mem_access_multi as the generated versions can't handle
 * correctly the translation of all fields from compat_(*) to xen_(*).
 */
#ifndef CHECK_hvm_altp2m_op
#define CHECK_hvm_altp2m_op \
    CHECK_SIZE_(struct, hvm_altp2m_op); \
    CHECK_FIELD_(struct, hvm_altp2m_op, version); \
    CHECK_FIELD_(struct, hvm_altp2m_op, cmd); \
    CHECK_FIELD_(struct, hvm_altp2m_op, domain); \
    CHECK_FIELD_(struct, hvm_altp2m_op, pad1); \
    CHECK_FIELD_(struct, hvm_altp2m_op, pad2)
#endif /* CHECK_hvm_altp2m_op */

#ifndef CHECK_hvm_altp2m_set_mem_access_multi
#define CHECK_hvm_altp2m_set_mem_access_multi \
    CHECK_FIELD_(struct, hvm_altp2m_set_mem_access_multi, view); \
    CHECK_FIELD_(struct, hvm_altp2m_set_mem_access_multi, pad); \
    CHECK_FIELD_(struct, hvm_altp2m_set_mem_access_multi, nr); \
    CHECK_FIELD_(struct, hvm_altp2m_set_mem_access_multi, opaque)
#endif /* CHECK_hvm_altp2m_set_mem_access_multi */

CHECK_hvm_altp2m_op;
CHECK_hvm_altp2m_set_mem_access_multi;

static int compat_altp2m_op(
    XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc = 0;
    struct compat_hvm_altp2m_op a;
    union
    {
        XEN_GUEST_HANDLE_PARAM(void) hnd;
        struct xen_hvm_altp2m_op *altp2m_op;
    } nat;

    if ( !hvm_altp2m_supported() )
        return -EOPNOTSUPP;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.pad1 || a.pad2 ||
         (a.version != HVMOP_ALTP2M_INTERFACE_VERSION) )
        return -EINVAL;

    set_xen_guest_handle(nat.hnd, COMPAT_ARG_XLAT_VIRT_BASE);

    switch ( a.cmd )
    {
    case HVMOP_altp2m_set_mem_access_multi:
#define XLAT_hvm_altp2m_set_mem_access_multi_HNDL_pfn_list(_d_, _s_); \
        guest_from_compat_handle((_d_)->pfn_list, (_s_)->pfn_list)
#define XLAT_hvm_altp2m_set_mem_access_multi_HNDL_access_list(_d_, _s_); \
        guest_from_compat_handle((_d_)->access_list, (_s_)->access_list)
        XLAT_hvm_altp2m_set_mem_access_multi(&nat.altp2m_op->u.set_mem_access_multi,
                                             &a.u.set_mem_access_multi);
#undef XLAT_hvm_altp2m_set_mem_access_multi_HNDL_pfn_list
#undef XLAT_hvm_altp2m_set_mem_access_multi_HNDL_access_list
        break;

    default:
        return do_altp2m_op(arg);
    }

    /* Manually fill the common part of the xen_hvm_altp2m_op structure. */
    nat.altp2m_op->version  = a.version;
    nat.altp2m_op->cmd      = a.cmd;
    nat.altp2m_op->domain   = a.domain;
    nat.altp2m_op->pad1     = a.pad1;
    nat.altp2m_op->pad2     = a.pad2;

    rc = do_altp2m_op(nat.hnd);

    switch ( a.cmd )
    {
    case HVMOP_altp2m_set_mem_access_multi:
        if ( rc == -ERESTART )
        {
            a.u.set_mem_access_multi.opaque =
                nat.altp2m_op->u.set_mem_access_multi.opaque;
            if ( __copy_field_to_guest(guest_handle_cast(arg,
                                                         compat_hvm_altp2m_op_t),
                                       &a, u.set_mem_access_multi.opaque) )
                rc = -EFAULT;
        }
        break;

    default:
        ASSERT_UNREACHABLE();
    }

    return rc;
}

static int hvmop_get_mem_type(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_get_mem_type_t) arg)
{
    struct xen_hvm_get_mem_type a;
    struct domain *d;
    p2m_type_t t;
    int rc;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    d = rcu_lock_domain_by_any_id(a.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_get_mem_type);
    if ( rc )
        goto out;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    /*
     * Use get_gfn query as we are interested in the current
     * type, not in allocating or unsharing. That'll happen
     * on access.
     */
    get_gfn_query_unlocked(d, a.pfn, &t);
    if ( p2m_is_mmio(t) )
        a.mem_type =  HVMMEM_mmio_dm;
    else if ( t == p2m_ioreq_server )
        a.mem_type = HVMMEM_ioreq_server;
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

    rc = -EFAULT;
    if ( __copy_to_guest(arg, &a, 1) )
        goto out;
    rc = 0;

 out:
    rcu_unlock_domain(d);

    return rc;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc = 0;

    /*
     * NB: hvm_op can be part of a restarted hypercall; but at the
     * moment the only hypercalls which do continuations don't need to
     * store any iteration information (since they're just re-trying
     * the acquisition of a lock).
     */

    switch ( op )
    {
    case HVMOP_set_evtchn_upcall_vector:
        rc = hvmop_set_evtchn_upcall_vector(
            guest_handle_cast(arg, xen_hvm_evtchn_upcall_vector_t));
        break;
    
    case HVMOP_set_param:
        rc = hvmop_set_param(
            guest_handle_cast(arg, xen_hvm_param_t));
        break;

    case HVMOP_get_param:
        rc = hvmop_get_param(
            guest_handle_cast(arg, xen_hvm_param_t));
        break;

    case HVMOP_flush_tlbs:
        rc = guest_handle_is_null(arg) ? hvmop_flush_tlb_all() : -EINVAL;
        break;

    case HVMOP_get_mem_type:
        rc = hvmop_get_mem_type(
            guest_handle_cast(arg, xen_hvm_get_mem_type_t));
        break;

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
        if ( unlikely(d != current->domain) )
            rc = -EOPNOTSUPP;
        else if ( is_hvm_domain(d) && paging_mode_shadow(d) )
            rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( !rc )
            pagetable_dying(a.gpa);

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

    case HVMOP_guest_request_vm_event:
        if ( guest_handle_is_null(arg) )
            monitor_guest_request();
        else
            rc = -EINVAL;
        break;

    case HVMOP_altp2m:
        rc = current->hcall_compat ? compat_altp2m_op(arg) : do_altp2m_op(arg);
        break;

    default:
    {
        gdprintk(XENLOG_DEBUG, "Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
        break;
    }
    }

    if ( rc == -ERESTART )
        rc = hypercall_create_continuation(__HYPERVISOR_hvm_op, "lh",
                                           op, arg);

    return rc;
}

int hvm_debug_op(struct vcpu *v, int32_t op)
{
    int rc;

    switch ( op )
    {
        case XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON:
        case XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF:
            rc = -EOPNOTSUPP;
            if ( !cpu_has_monitor_trap_flag )
                break;
            rc = 0;
            vcpu_pause(v);
            v->arch.hvm.single_step =
                (op == XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON);
            vcpu_unpause(v); /* guest will latch new state */
            break;
        default:
            rc = -ENOSYS;
            break;
    }

    return rc;
}

void hvm_toggle_singlestep(struct vcpu *v)
{
    ASSERT(atomic_read(&v->pause_count));

    if ( !hvm_is_singlestep_supported() )
        return;

    v->arch.hvm.single_step = !v->arch.hvm.single_step;
}

void hvm_domain_soft_reset(struct domain *d)
{
    hvm_destroy_all_ioreq_servers(d);
}

/*
 * Segment caches in VMCB/VMCS are inconsistent about which bits are checked,
 * important, and preserved across vmentry/exit.  Cook the values to make them
 * closer to what is architecturally expected from entries in the segment
 * cache.
 */
void hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg)
{
    alternative_vcall(hvm_funcs.get_segment_register, v, seg, reg);

    switch ( seg )
    {
    case x86_seg_ss:
        /* SVM may retain %ss.DB when %ss is loaded with a NULL selector. */
        if ( !reg->p )
            reg->db = 0;
        break;

    case x86_seg_tr:
        /*
         * SVM doesn't track %tr.B. Architecturally, a loaded TSS segment will
         * always be busy.
         */
        reg->type |= 0x2;

        /*
         * %cs and %tr are unconditionally present.  SVM ignores these present
         * bits and will happily run without them set.
         */
    case x86_seg_cs:
        reg->p = 1;
        break;

    case x86_seg_gdtr:
    case x86_seg_idtr:
        /*
         * Treat GDTR/IDTR as being present system segments.  This avoids them
         * needing special casing for segmentation checks.
         */
        reg->attr = 0x80;
        break;

    default: /* Avoid triggering -Werror=switch */
        break;
    }

    if ( reg->p )
    {
        /*
         * For segments which are present/usable, cook the system flag.  SVM
         * ignores the S bit on all segments and will happily run with them in
         * any state.
         */
        reg->s = is_x86_user_segment(seg);

        /*
         * SVM discards %cs.G on #VMEXIT.  Other user segments do have .G
         * tracked, but Linux commit 80112c89ed87 "KVM: Synthesize G bit for
         * all segments." indicates that this isn't necessarily the case when
         * nested under ESXi.
         *
         * Unconditionally recalculate G.
         */
        reg->g = !!(reg->limit >> 20);

        /*
         * SVM doesn't track the Accessed flag.  It will always be set for
         * usable user segments loaded into the descriptor cache.
         */
        if ( is_x86_user_segment(seg) )
            reg->type |= 0x1;
    }
}

void hvm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg)
{
    /* Set G to match the limit field.  VT-x cares, while SVM doesn't. */
    if ( reg->p )
        reg->g = !!(reg->limit >> 20);

    switch ( seg )
    {
    case x86_seg_cs:
        ASSERT(reg->p);                              /* Usable. */
        ASSERT(reg->s);                              /* User segment. */
        ASSERT(reg->type & 0x1);                     /* Accessed. */
        ASSERT((reg->base >> 32) == 0);              /* Upper bits clear. */
        break;

    case x86_seg_ss:
        if ( reg->p )
        {
            ASSERT(reg->s);                          /* User segment. */
            ASSERT(!(reg->type & 0x8));              /* Data segment. */
            ASSERT(reg->type & 0x2);                 /* Writeable. */
            ASSERT(reg->type & 0x1);                 /* Accessed. */
            ASSERT((reg->base >> 32) == 0);          /* Upper bits clear. */
        }
        break;

    case x86_seg_ds:
    case x86_seg_es:
    case x86_seg_fs:
    case x86_seg_gs:
        if ( reg->p )
        {
            ASSERT(reg->s);                          /* User segment. */

            if ( reg->type & 0x8 )
                ASSERT(reg->type & 0x2);             /* Readable. */

            ASSERT(reg->type & 0x1);                 /* Accessed. */

            if ( seg == x86_seg_fs || seg == x86_seg_gs )
                ASSERT(is_canonical_address(reg->base));
            else
                ASSERT((reg->base >> 32) == 0);      /* Upper bits clear. */
        }
        break;

    case x86_seg_tr:
        ASSERT(reg->p);                              /* Usable. */
        ASSERT(!reg->s);                             /* System segment. */
        ASSERT(!(reg->sel & 0x4));                   /* !TI. */
        if ( reg->type == SYS_DESC_tss_busy )
            ASSERT(is_canonical_address(reg->base));
        else if ( reg->type == SYS_DESC_tss16_busy )
            ASSERT((reg->base >> 32) == 0);
        else
            ASSERT(!"%tr typecheck failure");
        break;

    case x86_seg_ldtr:
        if ( reg->p )
        {
            ASSERT(!reg->s);                         /* System segment. */
            ASSERT(!(reg->sel & 0x4));               /* !TI. */
            ASSERT(reg->type == SYS_DESC_ldt);
            ASSERT(is_canonical_address(reg->base));
        }
        break;

    case x86_seg_gdtr:
    case x86_seg_idtr:
        ASSERT(is_canonical_address(reg->base));
        ASSERT((reg->limit >> 16) == 0);             /* Upper bits clear. */
        break;

    default:
        ASSERT_UNREACHABLE();
        return;
    }

    alternative_vcall(hvm_funcs.set_segment_register, v, seg, reg);
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

