/******************************************************************************
 * config.h
 *
 * A Linux-style configuration list.
 */

#ifndef __ARM_CONFIG_H__
#define __ARM_CONFIG_H__

#define CONFIG_PAGING_LEVELS 3

#define CONFIG_ARM 1

#define CONFIG_ARM_L1_CACHE_SHIFT 7 /* XXX */

#define CONFIG_SMP 1

#define CONFIG_DOMAIN_PAGE 1

#define OPT_CONSOLE_STR "com1"

#ifdef MAX_PHYS_CPUS
#define NR_CPUS MAX_PHYS_CPUS
#else
#define NR_CPUS 128
#endif

#define MAX_VIRT_CPUS 128 /* XXX */
#define MAX_HVM_VCPUS MAX_VIRT_CPUS

#define asmlinkage /* Nothing needed */

#define __LINUX_ARM_ARCH__ 7
#define CONFIG_AEABI

/* Linkage for ARM */
#define __ALIGN .align 2
#define __ALIGN_STR ".align 2"
#ifdef __ASSEMBLY__
#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR
#define ENTRY(name)                             \
  .globl name;                                  \
  ALIGN;                                        \
  name:
#define END(name) \
  .size name, .-name
#define ENDPROC(name) \
  .type name, %function; \
  END(name)
#endif

/*
 * Memory layout:
 *  0  -   2M   Unmapped
 *  2M -   4M   Xen text, data, bss
 *  4M -   6M   Fixmap: special-purpose 4K mapping slots
 *  6M  -  8M   Early boot misc (see below)
 *
 * 32M - 128M   Frametable: 24 bytes per page for 16GB of RAM
 *
 *  1G -   2G   Xenheap: always-mapped memory
 *  2G -   4G   Domheap: on-demand-mapped
 *
 * The early boot misc area is used:
 *   - in head.S for the DTB for device_tree_early_init().
 *   - in setup_pagetables() when relocating Xen.
 */

#define XEN_VIRT_START         0x00200000
#define FIXMAP_ADDR(n)        (0x00400000 + (n) * PAGE_SIZE)
#define BOOT_MISC_VIRT_START   0x00600000
#define FRAMETABLE_VIRT_START  0x02000000
#define XENHEAP_VIRT_START     0x40000000
#define DOMHEAP_VIRT_START     0x80000000

#define HYPERVISOR_VIRT_START mk_unsigned_long(XEN_VIRT_START)

#define DOMHEAP_ENTRIES        1024  /* 1024 2MB mapping slots */

/* Fixmap slots */
#define FIXMAP_CONSOLE  0  /* The primary UART */
#define FIXMAP_PT       1  /* Temporary mappings of pagetable pages */
#define FIXMAP_MISC     2  /* Ephemeral mappings of hardware */
#define FIXMAP_GICD     3  /* Interrupt controller: distributor registers */
#define FIXMAP_GICC1    4  /* Interrupt controller: CPU registers (first page) */
#define FIXMAP_GICC2    5  /* Interrupt controller: CPU registers (second page) */
#define FIXMAP_GICH     6  /* Interrupt controller: virtual interface control registers */

#define PAGE_SHIFT              12

#ifndef __ASSEMBLY__
#define PAGE_SIZE           (1L << PAGE_SHIFT)
#else
#define PAGE_SIZE           (1 << PAGE_SHIFT)
#endif
#define PAGE_MASK           (~(PAGE_SIZE-1))
#define PAGE_FLAG_MASK      (~0)

#define STACK_ORDER 3
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

#ifndef __ASSEMBLY__
extern unsigned long xen_phys_start;
extern unsigned long xenheap_phys_end;
extern unsigned long frametable_virt_end;
#endif

#define supervisor_mode_kernel (0)

#define watchdog_disable() ((void)0)
#define watchdog_enable()  ((void)0)

/* Board-specific: base address of PL011 UART */
#define EARLY_UART_ADDRESS 0x1c090000
/* Board-specific: base address of GIC + its regs */
#define GIC_BASE_ADDRESS 0x2c000000
#define GIC_DR_OFFSET 0x1000
#define GIC_CR_OFFSET 0x2000
#define GIC_HR_OFFSET 0x4000 /* Guess work http://lists.infradead.org/pipermail/linux-arm-kernel/2011-September/064219.html */
#define GIC_VR_OFFSET 0x6000 /* Virtual Machine CPU interface) */
/* Board-specific: base address of system controller */
#define SP810_ADDRESS 0x1C020000


#endif /* __ARM_CONFIG_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
