/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/types.h>
#include <asm/mpu.h>
#include <asm/sysregs.h>
#include <asm/system.h>

#define GENERATE_WRITE_PR_REG_CASE(num, pr)               \
    case num:                                             \
    {                                                     \
        WRITE_SYSREG(pr->prbar.bits, HPRBAR##num);        \
        WRITE_SYSREG(pr->prlar.bits, HPRLAR##num);        \
        break;                                            \
    }

#define GENERATE_WRITE_PR_REG_OTHERS(num, pr)             \
    case num:                                             \
    {                                                     \
        WRITE_SYSREG(pr->prbar.bits, HPRBAR);             \
        WRITE_SYSREG(pr->prlar.bits, HPRLAR);             \
        break;                                            \
    }

#define GENERATE_READ_PR_REG_CASE(num, pr)                \
    case num:                                             \
    {                                                     \
        pr->prbar.bits = READ_SYSREG(HPRBAR##num);        \
        pr->prlar.bits = READ_SYSREG(HPRLAR##num);        \
        break;                                            \
    }

#define GENERATE_READ_PR_REG_OTHERS(num, pr)              \
    case num:                                             \
    {                                                     \
        pr->prbar.bits = READ_SYSREG(HPRBAR);             \
        pr->prlar.bits = READ_SYSREG(HPRLAR);             \
        break;                                            \
    }

/*
 * Armv8-R supports direct access and indirect access to the MPU regions through
 * registers:
 *  - indirect access involves changing the MPU region selector, issuing an isb
 *    barrier and accessing the selected region through specific registers
 *  - direct access involves accessing specific registers that point to
 *    specific MPU regions, without changing the selector, avoiding the use of
 *    a barrier.
 * For Arm32 the HPR{B,L}AR<n> (for n=0..31) are used for direct access to the
 * first 32 MPU regions.
 * For MPU regions numbered 32..254, one needs to set the region number in
 * HPRSELR, followed by configuring HPR{B,L}AR.
 */
static void prepare_selector(uint8_t *sel)
{
    uint8_t cur_sel = *sel;
    /* The top 24 bits of HPRSELR are RES0. */
    uint8_t val = READ_SYSREG(HPRSELR) & 0xff;

    if ( (cur_sel > 31) && (cur_sel != val) )
    {
        WRITE_SYSREG(cur_sel, HPRSELR);
        isb();
    }
}

void read_protection_region(pr_t *pr_read, uint8_t sel)
{
    prepare_selector(&sel);

    switch ( sel )
    {
        GENERATE_READ_PR_REG_CASE(0, pr_read);
        GENERATE_READ_PR_REG_CASE(1, pr_read);
        GENERATE_READ_PR_REG_CASE(2, pr_read);
        GENERATE_READ_PR_REG_CASE(3, pr_read);
        GENERATE_READ_PR_REG_CASE(4, pr_read);
        GENERATE_READ_PR_REG_CASE(5, pr_read);
        GENERATE_READ_PR_REG_CASE(6, pr_read);
        GENERATE_READ_PR_REG_CASE(7, pr_read);
        GENERATE_READ_PR_REG_CASE(8, pr_read);
        GENERATE_READ_PR_REG_CASE(9, pr_read);
        GENERATE_READ_PR_REG_CASE(10, pr_read);
        GENERATE_READ_PR_REG_CASE(11, pr_read);
        GENERATE_READ_PR_REG_CASE(12, pr_read);
        GENERATE_READ_PR_REG_CASE(13, pr_read);
        GENERATE_READ_PR_REG_CASE(14, pr_read);
        GENERATE_READ_PR_REG_CASE(15, pr_read);
        GENERATE_READ_PR_REG_CASE(16, pr_read);
        GENERATE_READ_PR_REG_CASE(17, pr_read);
        GENERATE_READ_PR_REG_CASE(18, pr_read);
        GENERATE_READ_PR_REG_CASE(19, pr_read);
        GENERATE_READ_PR_REG_CASE(20, pr_read);
        GENERATE_READ_PR_REG_CASE(21, pr_read);
        GENERATE_READ_PR_REG_CASE(22, pr_read);
        GENERATE_READ_PR_REG_CASE(23, pr_read);
        GENERATE_READ_PR_REG_CASE(24, pr_read);
        GENERATE_READ_PR_REG_CASE(25, pr_read);
        GENERATE_READ_PR_REG_CASE(26, pr_read);
        GENERATE_READ_PR_REG_CASE(27, pr_read);
        GENERATE_READ_PR_REG_CASE(28, pr_read);
        GENERATE_READ_PR_REG_CASE(29, pr_read);
        GENERATE_READ_PR_REG_CASE(30, pr_read);
        GENERATE_READ_PR_REG_CASE(31, pr_read);
        GENERATE_READ_PR_REG_OTHERS(32 ... 254, pr_read);
    default:
        BUG(); /* Can't happen */
        break;
    }
}

void write_protection_region(const pr_t *pr_write, uint8_t sel)
{
    prepare_selector(&sel);

    switch ( sel )
    {
        GENERATE_WRITE_PR_REG_CASE(0, pr_write);
        GENERATE_WRITE_PR_REG_CASE(1, pr_write);
        GENERATE_WRITE_PR_REG_CASE(2, pr_write);
        GENERATE_WRITE_PR_REG_CASE(3, pr_write);
        GENERATE_WRITE_PR_REG_CASE(4, pr_write);
        GENERATE_WRITE_PR_REG_CASE(5, pr_write);
        GENERATE_WRITE_PR_REG_CASE(6, pr_write);
        GENERATE_WRITE_PR_REG_CASE(7, pr_write);
        GENERATE_WRITE_PR_REG_CASE(8, pr_write);
        GENERATE_WRITE_PR_REG_CASE(9, pr_write);
        GENERATE_WRITE_PR_REG_CASE(10, pr_write);
        GENERATE_WRITE_PR_REG_CASE(11, pr_write);
        GENERATE_WRITE_PR_REG_CASE(12, pr_write);
        GENERATE_WRITE_PR_REG_CASE(13, pr_write);
        GENERATE_WRITE_PR_REG_CASE(14, pr_write);
        GENERATE_WRITE_PR_REG_CASE(15, pr_write);
        GENERATE_WRITE_PR_REG_CASE(16, pr_write);
        GENERATE_WRITE_PR_REG_CASE(17, pr_write);
        GENERATE_WRITE_PR_REG_CASE(18, pr_write);
        GENERATE_WRITE_PR_REG_CASE(19, pr_write);
        GENERATE_WRITE_PR_REG_CASE(20, pr_write);
        GENERATE_WRITE_PR_REG_CASE(21, pr_write);
        GENERATE_WRITE_PR_REG_CASE(22, pr_write);
        GENERATE_WRITE_PR_REG_CASE(23, pr_write);
        GENERATE_WRITE_PR_REG_CASE(24, pr_write);
        GENERATE_WRITE_PR_REG_CASE(25, pr_write);
        GENERATE_WRITE_PR_REG_CASE(26, pr_write);
        GENERATE_WRITE_PR_REG_CASE(27, pr_write);
        GENERATE_WRITE_PR_REG_CASE(28, pr_write);
        GENERATE_WRITE_PR_REG_CASE(29, pr_write);
        GENERATE_WRITE_PR_REG_CASE(30, pr_write);
        GENERATE_WRITE_PR_REG_CASE(31, pr_write);
        GENERATE_WRITE_PR_REG_OTHERS(32 ... 254, pr_write);
    default:
        BUG(); /* Can't happen */
        break;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
