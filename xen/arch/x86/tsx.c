#include <xen/init.h>
#include <xen/param.h>
#include <asm/microcode.h>
#include <asm/msr.h>

/*
 * Valid values:
 *   1 => Explicit tsx=1
 *   0 => Explicit tsx=0
 *  -1 => Default, altered to 0/1 (if unspecified) by:
 *                 - TAA heuristics/settings for speculative safety
 *                 - "TSX vs PCR3" select for TSX memory ordering safety
 *  -2 => Implicit tsx=0 (from RTM_ALWAYS_ABORT vs RTM mismatch)
 *  -3 => Implicit tsx=1 (feed-through from spec-ctrl=0)
 *
 * This is arranged such that the bottom bit encodes whether TSX is actually
 * disabled, while identifying various explicit (>=0) and implicit (<0)
 * conditions.
 *
 * This option only has any effect on systems presenting a mechanism of
 * controlling TSX behaviour, and where TSX isn't force-disabled by firmware.
 */
int8_t __read_mostly opt_tsx = -1;
bool __read_mostly rtm_disabled;

static int __init cf_check parse_tsx(const char *s)
{
    int rc = 0, val = parse_bool(s, NULL);

    if ( val >= 0 )
        opt_tsx = val;
    else
        rc = -EINVAL;

    return rc;
}
custom_param("tsx", parse_tsx);

void tsx_init(void)
{
    static bool __read_mostly once;

    /*
     * This function is first called between microcode being loaded, and
     * CPUID being scanned generally. early_cpu_init() has already prepared
     * the feature bits needed here. And early_microcode_init() has ensured
     * they are not stale after the microcode update.
     */
    if ( unlikely(!once) )
    {
        bool has_rtm_always_abort;

        once = true;

        has_rtm_always_abort = cpu_has_rtm_always_abort;

        if ( cpu_has_tsx_ctrl && cpu_has_srbds_ctrl )
        {
            /*
             * On a TAA-vulnerable or later part with at least the May 2020
             * microcode mitigating SRBDS.
             */
            uint64_t val;

            rdmsrl(MSR_MCU_OPT_CTRL, val);

            /*
             * Probe for the February 2022 microcode which de-features TSX on
             * TAA-vulnerable client parts - WHL-R/CFL-R.
             *
             * RTM_ALWAYS_ABORT (read above) enumerates the new functionality,
             * but is read as zero if MCU_OPT_CTRL.RTM_ALLOW has been set
             * before we run.  Undo this.
             */
            if ( val & MCU_OPT_CTRL_RTM_ALLOW )
                has_rtm_always_abort = true;

            if ( has_rtm_always_abort )
            {
                if ( val & MCU_OPT_CTRL_RTM_LOCKED )
                {
                    /*
                     * If RTM_LOCKED is set, TSX is disabled because SGX is
                     * enabled, and there is nothing we can do.  Override with
                     * tsx=0 so all other logic takes sensible actions.
                     */
                    printk(XENLOG_WARNING "TSX locked by firmware - disabling\n");
                    opt_tsx = 0;
                }
                else
                {
                    /*
                     * Otherwise, set RTM_ALLOW.  Not because we necessarily
                     * intend to enable RTM, but it prevents
                     * MSR_TSX_CTRL.RTM_DISABLE from being ignored, thus
                     * allowing the rest of the TSX selection logic to work as
                     * before.
                     */
                    val |= MCU_OPT_CTRL_RTM_ALLOW;
                }

                set_in_mcu_opt_ctrl(
                    MCU_OPT_CTRL_RTM_LOCKED | MCU_OPT_CTRL_RTM_ALLOW, val);

                /*
                 * If no explicit tsx= option is provided, pick a default.
                 *
                 * With RTM_ALWAYS_ABORT, the default ucode behaviour is to
                 * disable, so match that.  This does not override explicit user
                 * choices, or implicit choices as a side effect of spec-ctrl=0.
                 */
                if ( opt_tsx == -1 )
                    opt_tsx = 0;
            }
        }

        if ( cpu_has_tsx_force_abort )
        {
            uint64_t val;

            /*
             * On an early TSX-enabled Skylake part subject to the memory
             * ordering erratum, with at least the March 2019 microcode.
             */

            rdmsrl(MSR_TSX_FORCE_ABORT, val);

            /*
             * At the time of writing (April 2024), it was discovered that
             * some parts (e.g. CoffeeLake 8th Gen, 06-9e-0a, ucode 0xf6)
             * advertise RTM_ALWAYS_ABORT, but XBEGIN instructions #UD.  Other
             * similar parts (e.g. KabyLake Xeon-E3, 06-9e-09, ucode 0xf8)
             * operate as expected.
             *
             * In this case:
             *  - RTM_ALWAYS_ABORT and MSR_TSX_FORCE_ABORT are enumerated.
             *  - XBEGIN instructions genuinely #UD.
             *  - MSR_TSX_FORCE_ABORT appears to be write-discard and fails to
             *    hold its value.
             *  - HLE and RTM are not enumerated, despite
             *    MSR_TSX_FORCE_ABORT.TSX_CPUID_CLEAR being clear.
             *
             * Spot RTM being unavailable without CLEAR_CPUID being set, and
             * treat it as if no TSX is available at all.  This will prevent
             * Xen from thinking it's safe to offer HLE/RTM to VMs.
             */
            if ( val == 0 && cpu_has_rtm_always_abort && !cpu_has_rtm )
            {
                printk(XENLOG_ERR
                       "FIRMWARE BUG: CPU %02x-%02x-%02x, ucode 0x%08x: RTM_ALWAYS_ABORT vs RTM mismatch\n",
                       boot_cpu_data.x86, boot_cpu_data.x86_model,
                       boot_cpu_data.x86_mask, this_cpu(cpu_sig).rev);

                setup_clear_cpu_cap(X86_FEATURE_RTM_ALWAYS_ABORT);
                setup_clear_cpu_cap(X86_FEATURE_TSX_FORCE_ABORT);

                if ( opt_tsx < 0 )
                    opt_tsx = -2;

                goto done_probe;
            }

            /*
             * Probe for the June 2021 microcode which de-features TSX on
             * client parts.  (Note - this is a subset of parts impacted by
             * the memory ordering errata.)
             *
             * RTM_ALWAYS_ABORT enumerates the new functionality, but is also
             * read as zero if TSX_FORCE_ABORT.ENABLE_RTM has been set before
             * we run.
             */
            if ( val & TSX_ENABLE_RTM )
                has_rtm_always_abort = true;

            /*
             * If no explicit tsx= option is provided, pick a default.
             *
             * This deliberately overrides the implicit opt_tsx=-3 from
             * `spec-ctrl=0` because:
             * - parse_spec_ctrl() ran before any CPU details where know.
             * - We now know we're running on a CPU not affected by TAA (as
             *   TSX_FORCE_ABORT is enumerated).
             * - When RTM_ALWAYS_ABORT is enumerated, TSX malfunctions, so we
             *   only ever want it enabled by explicit user choice.
             *
             * Without RTM_ALWAYS_ABORT, leave TSX active.  In particular,
             * this includes SKX where TSX is still supported.
             *
             * With RTM_ALWAYS_ABORT, disable TSX.
             */
            if ( opt_tsx < 0 )
                opt_tsx = !has_rtm_always_abort;
        }

        /*
         * Always force RTM_ALWAYS_ABORT, even if it currently visible.  If
         * the user explicitly opts to enable TSX, we'll set the appropriate
         * RTM_ENABLE bit and cause RTM_ALWAYS_ABORT to be hidden from the
         * general CPUID scan later.
         */
        if ( has_rtm_always_abort )
            setup_force_cpu_cap(X86_FEATURE_RTM_ALWAYS_ABORT);

        /*
         * The TSX features (HLE/RTM) are handled specially.  They both
         * enumerate features but, on certain parts, have mechanisms to be
         * hidden without disrupting running software.
         *
         * At the moment, we're running in an unknown context (WRT hiding -
         * particularly if another fully fledged kernel ran before us) and
         * depending on user settings, may elect to continue hiding them from
         * native CPUID instructions.
         *
         * Xen doesn't use TSX itself, but use cpu_has_{hle,rtm} for various
         * system reasons, mostly errata detection, so the meaning is more
         * useful as "TSX infrastructure available", as opposed to "features
         * advertised and working".
         *
         * Force the features to be visible in Xen's view if we see any of the
         * infrastructure capable of hiding them.
         */
        if ( cpu_has_tsx_ctrl || cpu_has_tsx_force_abort )
        {
            setup_force_cpu_cap(X86_FEATURE_HLE);
            setup_force_cpu_cap(X86_FEATURE_RTM);
        }
    }
 done_probe:

    /*
     * Note: MSR_TSX_CTRL is enumerated on TSX-enabled MDS_NO and later parts.
     * MSR_TSX_FORCE_ABORT is enumerated on TSX-enabled pre-MDS_NO Skylake
     * parts only.  The two features are on a disjoint set of CPUs, and not
     * offered to guests by hypervisors.
     */
    if ( cpu_has_tsx_ctrl )
    {
        /*
         * On a TAA-vulnerable part with at least the November 2019 microcode,
         * or newer part with TAA fixed.
         *
         * Notes:
         *  - With the February 2022 microcode, if SGX has caused TSX to be
         *    locked off, opt_tsx is overridden to 0.  TSX_CTRL.RTM_DISABLE is
         *    an ignored bit, but we write it such that it matches the
         *    behaviour enforced by microcode.
         *  - Otherwise, if SGX isn't enabled and TSX is available to be
         *    controlled, we have or will set MSR_MCU_OPT_CTRL.RTM_ALLOW to
         *    let TSX_CTRL.RTM_DISABLE be usable.
         */
        uint32_t hi, lo;

        rdmsr(MSR_TSX_CTRL, lo, hi);

        /* Check bottom bit only.  Higher bits are various sentinels. */
        rtm_disabled = !(opt_tsx & 1);

        lo &= ~(TSX_CTRL_RTM_DISABLE | TSX_CTRL_CPUID_CLEAR);
        if ( rtm_disabled )
            lo |= TSX_CTRL_RTM_DISABLE | TSX_CTRL_CPUID_CLEAR;

        wrmsr(MSR_TSX_CTRL, lo, hi);
    }
    else if ( cpu_has_tsx_force_abort )
    {
        /*
         * On an early TSX-enable Skylake part subject to the memory ordering
         * erratum, with at least the March 2019 microcode.
         */
        uint32_t hi, lo;

        rdmsr(MSR_TSX_FORCE_ABORT, lo, hi);

        /* Check bottom bit only.  Higher bits are various sentinels. */
        rtm_disabled = !(opt_tsx & 1);

        lo &= ~(TSX_FORCE_ABORT_RTM | TSX_CPUID_CLEAR | TSX_ENABLE_RTM);

        if ( cpu_has_rtm_always_abort )
        {
            /*
             * June 2021 microcode, on a client part with TSX de-featured:
             *  - There are no mitigations for the TSX memory ordering errata.
             *  - Performance counter 3 works.  (I.e. it isn't being used by
             *    microcode to work around the memory ordering errata.)
             *  - TSX_FORCE_ABORT.FORCE_ABORT_RTM is fixed read1/write-discard.
             *  - TSX_FORCE_ABORT.TSX_CPUID_CLEAR can be used to hide the
             *    HLE/RTM CPUID bits.
             *  - TSX_FORCE_ABORT.ENABLE_RTM may be used to opt in to
             *    re-enabling RTM, at the users own risk.
             */
            lo |= rtm_disabled ? TSX_CPUID_CLEAR : TSX_ENABLE_RTM;
        }
        else
        {
            /*
             * Either a server part where TSX isn't de-featured, or pre-June
             * 2021 microcode:
             *  - By default, the TSX memory ordering errata is worked around
             *    in microcode at the cost of Performance Counter 3.
             *  - "Working TSX" vs "Working PCR3" can be selected by way of
             *    setting TSX_FORCE_ABORT.FORCE_ABORT_RTM.
             */
            if ( rtm_disabled )
                lo |= TSX_FORCE_ABORT_RTM;
        }

        wrmsr(MSR_TSX_FORCE_ABORT, lo, hi);
    }
    else if ( opt_tsx >= 0 )
        printk_once(XENLOG_WARNING
                    "TSX controls not available - Ignoring tsx= setting\n");
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
