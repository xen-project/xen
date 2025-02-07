#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/riscv_encoding.h>

        .section .text.header, "ax", %progbits

        /*
         * OpenSBI pass to start():
         *   a0 -> hart_id ( bootcpu_id )
         *   a1 -> dtb_base 
         */
FUNC(start)
        /* Mask all interrupts */
        csrw    CSR_SIE, zero

        /*
         * Disable FPU to detect illegal usage of
         * floating point in kernel space
         */
        li      t0, SSTATUS_FS
        csrc    CSR_SSTATUS, t0

        /* Clear the BSS */
        la      t3, __bss_start
        la      t4, __bss_end
.L_clear_bss:
        REG_S   zero, (t3)
        add     t3, t3, __SIZEOF_POINTER__
        bltu    t3, t4, .L_clear_bss

        call    reset_stack

        /*
         * save hart_id ( bootcpu_id ) and dtb_base as a0 and a1 register can
         * be used by C code
         */
        mv      s0, a0
        mv      s1, a1

        call    calc_phys_offset
        mv      s2, a0

        call    setup_initial_pagetables

        /* Calculate proper VA after jump from 1:1 mapping */
        la      a0, .L_primary_switched
        sub     a0, a0, s2

        call    turn_on_mmu

.L_primary_switched:
        /*
         * cpu0_boot_stack address is 1:1 mapping related so it should be
         * recalculated after jump from 1:1 mapping world as 1:1 mapping
         * will be removed soon in start_xen().
         */
        call    reset_stack

        /* Xen's boot cpu id is equal to 0 so setup TP register for it */
        li      a0, 0
        call    setup_tp

        /* restore hart_id ( bootcpu_id ) and dtb address */
        mv      a0, s0
        mv      a1, s1

        tail    start_xen
END(start)

        .section .text, "ax", %progbits

FUNC(reset_stack)
        la      sp, cpu0_boot_stack
        li      t0, STACK_SIZE
        add     sp, sp, t0

        ret
END(reset_stack)

/* void setup_tp(unsigned int xen_cpuid); */
FUNC(setup_tp)
        la      t0, pcpu_info
        li      t1, PCPU_INFO_SIZE
        mul     t1, a0, t1
        add     tp, t0, t1
        ret
END(setup_tp)

        .section .text.ident, "ax", %progbits

FUNC(turn_on_mmu)
        sfence.vma

        li      t0, RV_STAGE1_MODE
        slli    t0, t0, SATP_MODE_SHIFT

        la      t1, stage1_pgtbl_root
        srli    t1, t1, PAGE_SHIFT
        or      t1, t1, t0
        csrw    CSR_SATP, t1

        jr      a0
END(turn_on_mmu)
