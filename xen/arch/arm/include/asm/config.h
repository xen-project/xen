/******************************************************************************
 * config.h
 *
 * A Linux-style configuration list.
 */

#ifndef __ARM_CONFIG_H__
#define __ARM_CONFIG_H__

#if defined(CONFIG_ARM_64)
# define LONG_BYTEORDER 3
# define ELFSIZE 64
#else
# define LONG_BYTEORDER 2
# define ELFSIZE 32
#endif

#define BYTES_PER_LONG (1 << LONG_BYTEORDER)
#define BITS_PER_LONG (BYTES_PER_LONG << 3)
#define POINTER_ALIGN BYTES_PER_LONG

#define BITS_PER_LLONG 64

/* xen_ulong_t is always 64 bits */
#define BITS_PER_XEN_ULONG 64

#define CONFIG_PAGING_LEVELS 3

#define CONFIG_ARM 1

#define CONFIG_ARM_L1_CACHE_SHIFT 7 /* XXX */

#define CONFIG_SMP 1

#define CONFIG_IRQ_HAS_MULTIPLE_ACTION 1

#define CONFIG_PAGEALLOC_MAX_ORDER 18
#define CONFIG_DOMU_MAX_ORDER      9
#define CONFIG_HWDOM_MAX_ORDER     10

#define OPT_CONSOLE_STR "dtuart"

#ifdef CONFIG_ARM_64
#define MAX_VIRT_CPUS 128u
#else
#define MAX_VIRT_CPUS 8u
#endif

#define INVALID_VCPU_ID MAX_VIRT_CPUS

#define __LINUX_ARM_ARCH__ 7
#define CONFIG_AEABI

/* Linkage for ARM */
#ifdef __ASSEMBLY__
#define ALIGN .align 2
#define ENTRY(name)                             \
  .globl name;                                  \
  ALIGN;                                        \
  name:
#define GLOBAL(name)                            \
  .globl name;                                  \
  name:
#define END(name) \
  .size name, .-name
#define ENDPROC(name) \
  .type name, %function; \
  END(name)
#endif

#include <xen/const.h>
#include <xen/page-size.h>

/*
 * ARM32 layout:
 *   0  -   2M   Unmapped
 *   2M -  10M   Xen text, data, bss
 *  10M -  12M   Fixmap: special-purpose 4K mapping slots
 *  12M -  16M   Early boot mapping of FDT
 *  16M -  18M   Livepatch vmap (if compiled in)
 *
 *  32M - 128M   Frametable: 32 bytes per page for 12GB of RAM
 * 256M -   1G   VMAP: ioremap and early_ioremap use this virtual address
 *                    space
 *
 *   1G -   2G   Xenheap: always-mapped memory
 *   2G -   4G   Domheap: on-demand-mapped
 *
 * ARM64 layout:
 * 0x0000000000000000 - 0x000001ffffffffff (2TB, L0 slots [0..3])
 *
 *  Reserved to identity map Xen
 *
 * 0x0000020000000000 - 0x0000027fffffffff (512GB, L0 slot [4])
 *  (Relative offsets)
 *   0  -   2M   Unmapped
 *   2M -  10M   Xen text, data, bss
 *  10M -  12M   Fixmap: special-purpose 4K mapping slots
 *  12M -  16M   Early boot mapping of FDT
 *  16M -  18M   Livepatch vmap (if compiled in)
 *
 *   1G -   2G   VMAP: ioremap and early_ioremap
 *
 *  32G -  64G   Frametable: 56 bytes per page for 2TB of RAM
 *
 * 0x0000028000000000 - 0x00007fffffffffff (125TB, L0 slots [5..255])
 *  Unused
 *
 * 0x0000800000000000 - 0x000084ffffffffff (5TB, L0 slots [256..265])
 *  1:1 mapping of RAM
 *
 * 0x0000850000000000 - 0x0000ffffffffffff (123TB, L0 slots [266..511])
 *  Unused
 */

#ifdef CONFIG_ARM_32
#define XEN_VIRT_START          _AT(vaddr_t, MB(2))
#else

#define SLOT0_ENTRY_BITS  39
#define SLOT0(slot) (_AT(vaddr_t,slot) << SLOT0_ENTRY_BITS)
#define SLOT0_ENTRY_SIZE  SLOT0(1)

#define XEN_VIRT_START          (SLOT0(4) + _AT(vaddr_t, MB(2)))
#endif

/*
 * Reserve enough space so both UBSAN and GCOV can be enabled together
 * plus some slack for future growth.
 */
#define XEN_VIRT_SIZE           _AT(vaddr_t, MB(8))
#define XEN_NR_ENTRIES(lvl)     (XEN_VIRT_SIZE / XEN_PT_LEVEL_SIZE(lvl))

#define FIXMAP_VIRT_START       (XEN_VIRT_START + XEN_VIRT_SIZE)
#define FIXMAP_VIRT_SIZE        _AT(vaddr_t, MB(2))

#define FIXMAP_ADDR(n)          (FIXMAP_VIRT_START + (n) * PAGE_SIZE)

#define BOOT_FDT_VIRT_START     (FIXMAP_VIRT_START + FIXMAP_VIRT_SIZE)
#define BOOT_FDT_VIRT_SIZE      _AT(vaddr_t, MB(4))

#ifdef CONFIG_LIVEPATCH
#define LIVEPATCH_VMAP_START    (BOOT_FDT_VIRT_START + BOOT_FDT_VIRT_SIZE)
#define LIVEPATCH_VMAP_SIZE    _AT(vaddr_t, MB(2))
#endif

#define HYPERVISOR_VIRT_START  XEN_VIRT_START

#ifdef CONFIG_ARM_32

#define CONFIG_SEPARATE_XENHEAP 1

#define FRAMETABLE_VIRT_START  _AT(vaddr_t, MB(32))
#define FRAMETABLE_SIZE        MB(128-32)
#define FRAMETABLE_NR          (FRAMETABLE_SIZE / sizeof(*frame_table))

#define VMAP_VIRT_START        _AT(vaddr_t, MB(256))
#define VMAP_VIRT_SIZE         _AT(vaddr_t, GB(1) - MB(256))

#define XENHEAP_VIRT_START     _AT(vaddr_t, GB(1))
#define XENHEAP_VIRT_SIZE      _AT(vaddr_t, GB(1))

#define DOMHEAP_VIRT_START     _AT(vaddr_t, GB(2))
#define DOMHEAP_VIRT_SIZE      _AT(vaddr_t, GB(2))

#define DOMHEAP_ENTRIES        1024  /* 1024 2MB mapping slots */

/* Number of domheap pagetable pages required at the second level (2MB mappings) */
#define DOMHEAP_SECOND_PAGES (DOMHEAP_VIRT_SIZE >> FIRST_SHIFT)

/*
 * The temporary area is overlapping with the domheap area. This may
 * be used to create an alias of the first slot containing Xen mappings
 * when turning on/off the MMU.
 */
#define TEMPORARY_AREA_FIRST_SLOT    (first_table_offset(DOMHEAP_VIRT_START))

/* Calculate the address in the temporary area */
#define TEMPORARY_AREA_ADDR(addr)                           \
     (((addr) & ~XEN_PT_LEVEL_MASK(1)) |                    \
      (TEMPORARY_AREA_FIRST_SLOT << XEN_PT_LEVEL_SHIFT(1)))

#define TEMPORARY_XEN_VIRT_START    TEMPORARY_AREA_ADDR(XEN_VIRT_START)

#else /* ARM_64 */

#define IDENTITY_MAPPING_AREA_NR_L0  4

#define VMAP_VIRT_START  (SLOT0(4) + GB(1))
#define VMAP_VIRT_SIZE   GB(1)

#define FRAMETABLE_VIRT_START  (SLOT0(4) + GB(32))
#define FRAMETABLE_SIZE        GB(32)
#define FRAMETABLE_NR          (FRAMETABLE_SIZE / sizeof(*frame_table))

#define DIRECTMAP_VIRT_START   SLOT0(256)
#define DIRECTMAP_SIZE         (SLOT0_ENTRY_SIZE * (266 - 256))
#define DIRECTMAP_VIRT_END     (DIRECTMAP_VIRT_START + DIRECTMAP_SIZE - 1)

#define XENHEAP_VIRT_START     directmap_virt_start

#define HYPERVISOR_VIRT_END    DIRECTMAP_VIRT_END

#endif

#define NR_hypercalls 64

#define STACK_ORDER 3
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

#ifndef __ASSEMBLY__
extern unsigned long frametable_virt_end;
#endif

#define watchdog_disable() ((void)0)
#define watchdog_enable()  ((void)0)

#if defined(__ASSEMBLY__) && !defined(LINKER_SCRIPT)
#include <asm/asm_defns.h>
#include <asm/macros.h>
#endif

#endif /* __ARM_CONFIG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
