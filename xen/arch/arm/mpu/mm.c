/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <xen/types.h>
#include <asm/mpu.h>
#include <asm/mpu/mm.h>
#include <asm/sysregs.h>

struct page_info *frame_table;

/* Maximum number of supported MPU memory regions by the EL2 MPU. */
uint8_t __ro_after_init max_mpu_regions;

/*
 * Bitmap xen_mpumap_mask is to record the usage of EL2 MPU memory regions.
 * Bit 0 represents MPU memory region 0, bit 1 represents MPU memory
 * region 1, ..., and so on.
 * If a MPU memory region gets enabled, set the according bit to 1.
 */
DECLARE_BITMAP(xen_mpumap_mask, MAX_MPU_REGION_NR) \
    __cacheline_aligned __section(".data");

/* EL2 Xen MPU memory region mapping table. */
pr_t __cacheline_aligned __section(".data") xen_mpumap[MAX_MPU_REGION_NR];

#ifdef CONFIG_ARM_64
/*
 * The following are needed for the cases: GENERATE_WRITE_PR_REG_CASE
 * and GENERATE_READ_PR_REG_CASE with num==0
 */
#define PRBAR0_EL2 PRBAR_EL2
#define PRLAR0_EL2 PRLAR_EL2

#define PRBAR_EL2_(n)   PRBAR##n##_EL2
#define PRLAR_EL2_(n)   PRLAR##n##_EL2

#endif /* CONFIG_ARM_64 */

#define GENERATE_WRITE_PR_REG_CASE(num, pr)                                 \
    case num:                                                               \
    {                                                                       \
        WRITE_SYSREG(pr->prbar.bits & ~MPU_REGION_RES0, PRBAR_EL2_(num));   \
        WRITE_SYSREG(pr->prlar.bits & ~MPU_REGION_RES0, PRLAR_EL2_(num));   \
        break;                                                              \
    }

#define GENERATE_READ_PR_REG_CASE(num, pr)                      \
    case num:                                                   \
    {                                                           \
        pr->prbar.bits = READ_SYSREG(PRBAR_EL2_(num));          \
        pr->prlar.bits = READ_SYSREG(PRLAR_EL2_(num));          \
        break;                                                  \
    }

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Unlike MMU, MPU does not use pages for translation. However, we continue
     * to use PAGE_SIZE to denote 4KB. This is so that the existing memory
     * management based on pages, continue to work for now.
     */
    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);
}

#ifdef CONFIG_ARM_64
/*
 * Armv8-R supports direct access and indirect access to the MPU regions through
 * registers:
 *  - indirect access involves changing the MPU region selector, issuing an isb
 *    barrier and accessing the selected region through specific registers
 *  - direct access involves accessing specific registers that point to
 *    specific MPU regions, without changing the selector, avoiding the use of
 *    a barrier.
 * For Arm64 the PR{B,L}AR_ELx (for n=0) and PR{B,L}AR<n>_ELx (for n=1..15) are
 * used for the direct access to the regions selected by
 * PRSELR_EL2.REGION<7:4>:n, so 16 regions can be directly accessed when the
 * selector is a multiple of 16, giving access to all the supported memory
 * regions.
 */
static void prepare_selector(uint8_t *sel)
{
    uint8_t cur_sel = *sel;

    /*
     * {read,write}_protection_region works using the direct access to the 0..15
     * regions, so in order to save the isb() overhead, change the PRSELR_EL2
     * only when needed, so when the upper 4 bits of the selector will change.
     */
    cur_sel &= 0xF0U;
    if ( READ_SYSREG(PRSELR_EL2) != cur_sel )
    {
        WRITE_SYSREG(cur_sel, PRSELR_EL2);
        isb();
    }
    *sel &= 0xFU;
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
    default:
        BUG(); /* Can't happen */
        break;
    }
}
#endif /* CONFIG_ARM_64 */

void __init setup_mm(void)
{
    BUG_ON("unimplemented");
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int nf)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

void dump_hyp_walk(vaddr_t addr)
{
    BUG_ON("unimplemented");
}

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void)
{
    BUG_ON("unimplemented");
}

void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned int flags)
{
    BUG_ON("unimplemented");
    return NULL;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
