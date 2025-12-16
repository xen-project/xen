/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/macros.h>
#include <xen/sections.h>

#include <asm/csr.h>
#include <asm/flushtlb.h>
#include <asm/p2m.h>
#include <asm/riscv_encoding.h>

static struct gstage_mode_desc __ro_after_init max_gstage_mode = {
    .mode = HGATP_MODE_OFF,
    .paging_levels = 0,
    .name = "Bare",
};

unsigned char get_max_supported_mode(void)
{
    return max_gstage_mode.mode;
}

static void __init gstage_mode_detect(void)
{
    static const struct gstage_mode_desc modes[] __initconst = {
        /*
         * Based on the RISC-V spec:
         *   Bare mode is always supported, regardless of SXLEN.
         *   When SXLEN=32, the only other valid setting for MODE is Sv32.
         *   When SXLEN=64, three paged virtual-memory schemes are defined:
         *   Sv39, Sv48, and Sv57.
         */
#ifdef CONFIG_RISCV_32
        { HGATP_MODE_SV32X4, 2, "Sv32x4" }
#else
        { HGATP_MODE_SV39X4, 3, "Sv39x4" },
        { HGATP_MODE_SV48X4, 4, "Sv48x4" },
        { HGATP_MODE_SV57X4, 5, "Sv57x4" },
#endif
    };

    for ( unsigned int mode_idx = ARRAY_SIZE(modes); mode_idx-- > 0; )
    {
        unsigned long mode = modes[mode_idx].mode;

        csr_write(CSR_HGATP, MASK_INSR(mode, HGATP_MODE_MASK));

        if ( MASK_EXTR(csr_read(CSR_HGATP), HGATP_MODE_MASK) == mode )
        {
            max_gstage_mode = modes[mode_idx];

            break;
        }
    }

    if ( max_gstage_mode.mode == HGATP_MODE_OFF )
        panic("Xen expects that G-stage won't be Bare mode\n");

    printk("Max supported G-stage mode is %s\n", max_gstage_mode.name);

    csr_write(CSR_HGATP, 0);

    /* local_hfence_gvma_all() will be called at the end of guest_mm_init. */
}

void __init guest_mm_init(void)
{
    gstage_mode_detect();

    /*
     * As gstage_mode_detect() is changing CSR_HGATP, it is necessary to flush
     * guest TLB because:
     *
     * From RISC-V spec:
     *   Speculative executions of the address-translation algorithm behave as
     *   non-speculative executions of the algorithm do, except that they must
     *   not set the dirty bit for a PTE, they must not trigger an exception,
     *   and they must not create address-translation cache entries if those
     *   entries would have been invalidated by any SFENCE.VMA instruction
     *   executed by the hart since the speculative execution of the algorithm
     *   began.
     *
     * Also, despite of the fact here it is mentioned that when V=0 two-stage
     * address translation is inactivated:
     *   The current virtualization mode, denoted V, indicates whether the hart
     *   is currently executing in a guest. When V=1, the hart is either in
     *   virtual S-mode (VS-mode), or in virtual U-mode (VU-mode) atop a guest
     *   OS running in VS-mode. When V=0, the hart is either in M-mode, in
     *   HS-mode, or in U-mode atop an OS running in HS-mode. The
     *   virtualization mode also indicates whether two-stage address
     *   translation is active (V=1) or inactive (V=0).
     * But on the same side, writing to hgatp register activates it:
     *   The hgatp register is considered active for the purposes of
     *   the address-translation algorithm unless the effective privilege mode
     *   is U and hstatus.HU=0.
     *
     * Thereby it leaves some room for speculation even in this stage of boot,
     * so it could be that we polluted local TLB so flush all guest TLB.
     */
    local_hfence_gvma_all();
}
