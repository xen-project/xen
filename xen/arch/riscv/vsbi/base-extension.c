
/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/version.h>

#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/vsbi.h>

/* Xen-controlled SBI version reported to guests */
#define XEN_SBI_VER_MAJOR 0
#define XEN_SBI_VER_MINOR 2

static int vsbi_base_ecall_handler(unsigned long eid, unsigned long fid,
                                   struct cpu_user_regs *regs)
{
    int ret = 0;
    struct sbiret sbi_ret;

    ASSERT(eid == SBI_EXT_BASE);

    switch ( fid )
    {
    case SBI_EXT_BASE_GET_SPEC_VERSION:
        regs->a1 = MASK_INSR(XEN_SBI_VER_MAJOR, SBI_SPEC_VERSION_MAJOR_MASK) |
                   XEN_SBI_VER_MINOR;
        break;

    case SBI_EXT_BASE_GET_IMP_ID:
        regs->a1 = SBI_XEN_IMPID;
        break;

    case SBI_EXT_BASE_GET_IMP_VERSION:
        regs->a1 = (xen_major_version() << 16) | xen_minor_version();
        break;

    case SBI_EXT_BASE_GET_MVENDORID:
    case SBI_EXT_BASE_GET_MARCHID:
    case SBI_EXT_BASE_GET_MIMPID:
        if ( is_hardware_domain(current->domain) )
        {
            sbi_ret = sbi_ecall(SBI_EXT_BASE, fid, 0, 0, 0, 0, 0, 0);
            ret = sbi_ret.error;
            regs->a1 = sbi_ret.value;
        }
        else
            /*
             * vSBI should present a consistent, virtualized view to guests.
             * In particular, DomU-visible data must remain stable across
             * migration and must not expose hardware-specific details.
             *
             * These register(s) must be readable in any implementation,
             * but a value of 0 can be returned to indicate the field
             * is not implemented.
             */
            regs->a1 = 0;

        break;

    case SBI_EXT_BASE_PROBE_EXT:
        regs->a1 = vsbi_find_extension(regs->a0) ? 1 : 0;
        break;

    default:
        /*
         * TODO: domain_crash() is acceptable here while things are still under
         * development.
         * It shouldn't stay like this in the end though: guests should not
         * be punished like this for something Xen hasn't implemented.
         */
        domain_crash(current->domain,
                     "%s: Unsupported ecall: EID: #%#lx FID: #%lu\n",
                     __func__, eid, fid);
        break;
    }

    return ret;
}

VSBI_EXT(base, SBI_EXT_BASE, SBI_EXT_BASE, vsbi_base_ecall_handler)
