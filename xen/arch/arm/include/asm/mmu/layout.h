/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MMU_LAYOUT_H__
#define __ARM_MMU_LAYOUT_H__

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
 * 0x0000000000000000 - 0x000009ffffffffff (10TB, L0 slots [0..19])
 *
 *  Reserved to identity map Xen
 *
 * 0x00000a0000000000 - 0x00000a7fffffffff (512GB, L0 slot [20])
 *  (Relative offsets)
 *   0  -   2M   Unmapped
 *   2M -  10M   Xen text, data, bss
 *  10M -  12M   Fixmap: special-purpose 4K mapping slots
 *  12M -  16M   Early boot mapping of FDT
 *  16M -  18M   Livepatch vmap (if compiled in)
 *  16M -  24M   Cache-colored Xen text, data, bss (temporary, if compiled in)
 *
 *   1G -   2G   VMAP: ioremap and early_ioremap
 *
 *  32G -  64G   Frametable: 56 bytes per page for 2TB of RAM
 *
 * 0x00000a8000000000 - 0x00007fffffffffff (512GB+117TB, L0 slots [21..255])
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

#define IDENTITY_MAPPING_AREA_NR_L0     20
#define XEN_VM_MAPPING                  SLOT0(IDENTITY_MAPPING_AREA_NR_L0)

#define SLOT0_ENTRY_BITS  39
#define SLOT0(slot) (_AT(vaddr_t,slot) << SLOT0_ENTRY_BITS)
#define SLOT0_ENTRY_SIZE  SLOT0(1)

#define XEN_VIRT_START          (XEN_VM_MAPPING + _AT(vaddr_t, MB(2)))
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

#define BOOT_RELOC_VIRT_START   (BOOT_FDT_VIRT_START + BOOT_FDT_VIRT_SIZE)

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
#define TEMPORARY_FIXMAP_VIRT_START TEMPORARY_AREA_ADDR(FIXMAP_VIRT_START)

#define TEMPORARY_FIXMAP_ADDR(n)                    \
     (TEMPORARY_FIXMAP_VIRT_START + (n) * PAGE_SIZE)

#else /* ARM_64 */

#define VMAP_VIRT_START  (XEN_VM_MAPPING + GB(1))
#define VMAP_VIRT_SIZE   GB(1)

#define FRAMETABLE_VIRT_START  (XEN_VM_MAPPING + GB(32))
#define FRAMETABLE_SIZE        GB(32)
#define FRAMETABLE_NR          (FRAMETABLE_SIZE / sizeof(*frame_table))

#define DIRECTMAP_VIRT_START   SLOT0(256)
#define DIRECTMAP_SIZE         (SLOT0_ENTRY_SIZE * (266 - 256))
#define DIRECTMAP_VIRT_END     (DIRECTMAP_VIRT_START + DIRECTMAP_SIZE - 1)

#define XENHEAP_VIRT_START     directmap_virt_start

#define HYPERVISOR_VIRT_END    DIRECTMAP_VIRT_END

#endif

#endif /* __ARM_MMU_LAYOUT_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
