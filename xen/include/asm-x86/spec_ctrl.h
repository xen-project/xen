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

/*
 * Encoding of:
 *   cpuinfo.spec_ctrl_flags
 *   default_spec_ctrl_flags
 *   domain.spec_ctrl_flags
 *
 * Live settings are in the top-of-stack block, because they need to be
 * accessable when XPTI is active.  Some settings are fixed from boot, some
 * context switched per domain, and some inhibited in the S3 path.
 */
#define SCF_use_shadow (1 << 0)
#define SCF_ist_sc_msr (1 << 1)
#define SCF_ist_rsb    (1 << 2)
#define SCF_verw       (1 << 3)
#define SCF_ist_ibpb   (1 << 4)
#define SCF_entry_ibpb (1 << 5)

/*
 * The IST paths (NMI/#MC) can interrupt any arbitrary context.  Some
 * functionality requires updated microcode to work.
 *
 * On boot, this is easy; we load microcode before figuring out which
 * speculative protections to apply.  However, on the S3 resume path, we must
 * be able to disable the configured mitigations until microcode is reloaded.
 *
 * These are the controls to inhibit on the S3 resume path until microcode has
 * been reloaded.
 */
#define SCF_IST_MASK (SCF_ist_sc_msr | SCF_ist_ibpb)

/*
 * Some speculative protections are per-domain.  These settings are merged
 * into the top-of-stack block in the context switch path.
 */
#define SCF_DOM_MASK (SCF_verw | SCF_entry_ibpb)

#ifndef __ASSEMBLY__

#include <asm/alternative.h>
#include <asm/current.h>
#include <asm/msr-index.h>

void init_speculation_mitigations(void);
void spec_ctrl_init_domain(struct domain *d);

/*
 * Switch to a new guest prediction context.
 *
 * This flushes all indirect branch predictors (BTB, RSB/RAS), so guest code
 * which has previously run on this CPU can't attack subsequent guest code.
 *
 * As this flushes the RSB/RAS, it destroys the predictions of the calling
 * context.  For best performace, arrange for this to be used when we're going
 * to jump out of the current context, e.g. with reset_stack_and_jump().
 *
 * For hardware which mis-implements IBPB, fix up by flushing the RSB/RAS
 * manually.
 */
static always_inline void spec_ctrl_new_guest_context(void)
{
    wrmsrl(MSR_PRED_CMD, PRED_CMD_IBPB);

    /* (ab)use alternative_input() to specify clobbers. */
    alternative_input("", "DO_OVERWRITE_RSB", X86_BUG_IBPB_NO_RET,
                      : "rax", "rcx");
}

extern int8_t opt_ibpb_ctxt_switch;
extern bool opt_ssbd;
extern int8_t opt_eager_fpu;
extern int8_t opt_l1d_flush;
extern bool opt_branch_harden;

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

extern uint64_t default_xen_mcu_opt_ctrl;

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
     * It is recommended in some cases to clear MSR_SPEC_CTRL when going idle,
     * to avoid impacting sibling threads.
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
     * Restore MSR_SPEC_CTRL on exit from idle.
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
