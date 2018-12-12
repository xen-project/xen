/******************************************************************************
 * include/asm-x86/spec_ctrl.h
 *
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */

#ifndef __X86_SPEC_CTRL_H__
#define __X86_SPEC_CTRL_H__

/* Encoding of cpuinfo.spec_ctrl_flags */
#define SCF_use_shadow (1 << 0)
#define SCF_ist_wrmsr  (1 << 1)
#define SCF_ist_rsb    (1 << 2)

#ifndef __ASSEMBLY__

#include <asm/alternative.h>
#include <asm/current.h>
#include <asm/msr-index.h>

void init_speculation_mitigations(void);

extern bool opt_ibpb;
extern bool opt_ssbd;
extern int8_t opt_eager_fpu;
extern int8_t opt_l1d_flush;

extern bool bsp_delay_spec_ctrl;
extern uint8_t default_xen_spec_ctrl;
extern uint8_t default_spec_ctrl_flags;

extern int8_t opt_xpti_hwdom, opt_xpti_domu;

extern int8_t opt_pv_l1tf_hwdom, opt_pv_l1tf_domu;

/*
 * The L1D address mask, which might be wider than reported in CPUID, and the
 * system physical address above which there are believed to be no cacheable
 * memory regions, thus unable to leak data via the L1TF vulnerability.
 */
extern paddr_t l1tf_addr_mask, l1tf_safe_maddr;

static inline void init_shadow_spec_ctrl_state(void)
{
    struct cpu_info *info = get_cpu_info();

    info->shadow_spec_ctrl = 0;
    info->xen_spec_ctrl = default_xen_spec_ctrl;
    info->spec_ctrl_flags = default_spec_ctrl_flags;

    /*
     * For least latency, the VERW selector should be a writeable data
     * descriptor resident in the cache.  __HYPERVISOR_DS32 shares a cache
     * line with __HYPERVISOR_CS, so is expected to be very cache-hot.
     */
    info->verw_sel = __HYPERVISOR_DS32;
}

/* WARNING! `ret`, `call *`, `jmp *` not safe after this call. */
static always_inline void spec_ctrl_enter_idle(struct cpu_info *info)
{
    uint32_t val = 0;

    /*
     * Branch Target Injection:
     *
     * Latch the new shadow value, then enable shadowing, then update the MSR.
     * There are no SMP issues here; only local processor ordering concerns.
     */
    info->shadow_spec_ctrl = val;
    barrier();
    info->spec_ctrl_flags |= SCF_use_shadow;
    barrier();
    alternative_input("", "wrmsr", X86_FEATURE_SC_MSR_IDLE,
                      "a" (val), "c" (MSR_SPEC_CTRL), "d" (0));
    barrier();

    /*
     * Microarchitectural Store Buffer Data Sampling:
     *
     * On vulnerable systems, store buffer entries are statically partitioned
     * between active threads.  When entering idle, our store buffer entries
     * are re-partitioned to allow the other threads to use them.
     *
     * Flush the buffers to ensure that no sensitive data of ours can be
     * leaked by a sibling after it gets our store buffer entries.
     *
     * Note: VERW must be encoded with a memory operand, as it is only that
     * form which causes a flush.
     */
    alternative_input("", "verw %[sel]", X86_FEATURE_SC_VERW_IDLE,
                      [sel] "m" (info->verw_sel));
}

/* WARNING! `ret`, `call *`, `jmp *` not safe before this call. */
static always_inline void spec_ctrl_exit_idle(struct cpu_info *info)
{
    uint32_t val = info->xen_spec_ctrl;

    /*
     * Branch Target Injection:
     *
     * Disable shadowing before updating the MSR.  There are no SMP issues
     * here; only local processor ordering concerns.
     */
    info->spec_ctrl_flags &= ~SCF_use_shadow;
    barrier();
    alternative_input("", "wrmsr", X86_FEATURE_SC_MSR_IDLE,
                      "a" (val), "c" (MSR_SPEC_CTRL), "d" (0));
    barrier();

    /*
     * Microarchitectural Store Buffer Data Sampling:
     *
     * On vulnerable systems, store buffer entries are statically partitioned
     * between active threads.  When exiting idle, the other threads store
     * buffer entries are re-partitioned to give us some.
     *
     * We now have store buffer entries with stale data from sibling threads.
     * A flush if necessary will be performed on the return to guest path.
     */
}

#endif /* __ASSEMBLY__ */
#endif /* !__X86_SPEC_CTRL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
