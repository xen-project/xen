/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__CONFIG_H
#define ASM__RISCV__CONFIG_H

#include <xen/const.h>
#include <xen/page-size.h>

#include <asm/riscv_encoding.h>

#ifdef CONFIG_RISCV_64
#define CONFIG_PAGING_LEVELS 3
#define RV_STAGE1_MODE SATP_MODE_SV39
#else
#define CONFIG_PAGING_LEVELS 2
#define RV_STAGE1_MODE SATP_MODE_SV32
#endif

/*
 * RISC-V64 Layout:
 *
#if RV_STAGE1_MODE == SATP_MODE_SV39
 *
 * From the riscv-privileged doc:
 *   When mapping between narrower and wider addresses,
 *   RISC-V zero-extends a narrower physical address to a wider size.
 *   The mapping between 64-bit virtual addresses and the 39-bit usable
 *   address space of Sv39 is not based on zero-extension but instead
 *   follows an entrenched convention that allows an OS to use one or
 *   a few of the most-significant bits of a full-size (64-bit) virtual
 *   address to quickly distinguish user and supervisor address regions.
 *
 * It means that:
 *   top VA bits are simply ignored for the purpose of translating to PA.
 *
 * Amount of slots for Frametable were calculated base on
 * sizeof(struct page_info) = 48. If the 'struct page_info' is changed,
 * the table below must be updated.
 *
 * ============================================================================
 * Start addr          | End addr         | Slot       | area description
 * ============================================================================
 *                   .....                 L2 511          Unused
 *  0xffffffffc0a00000  0xffffffffc0bfffff L2 511          Fixmap
 *                   ..... ( 2 MB gap )
 *  0xffffffffc0400000  0xffffffffc07fffff L2 511          FDT
 *                   ..... ( 2 MB gap )
 *  0xffffffffc0000000  0xffffffffc01fffff L2 511          Xen
 *                   .....                 L2 510          Unused
 *  0x3200000000        0x7f7fffffff       L2 200-509      Direct map
 *                   .....                 L2 199          Unused
 *  0x30c0000000        0x31bfffffff       L2 195-198      Frametable
 *                   .....                 L2 194          Unused
 *  0x3040000000        0x307fffffff       L2 193          VMAP
 *                   .....                 L2 0-192        Unused
#elif RV_STAGE1_MODE == SATP_MODE_SV48
 * Memory layout is the same as for SV39 in terms of slots, so only start and
 * end addresses should be shifted by 9
#endif
 */

#define HYP_PT_ROOT_LEVEL (CONFIG_PAGING_LEVELS - 1)

#ifdef CONFIG_RISCV_64

#define VPN_BITS (9)

#define SLOTN_ENTRY_BITS        (HYP_PT_ROOT_LEVEL * VPN_BITS + PAGE_SHIFT)
#define SLOTN(slot)             (_AT(vaddr_t, slot) << SLOTN_ENTRY_BITS)

#if RV_STAGE1_MODE == SATP_MODE_SV39
#define XEN_VIRT_START 0xFFFFFFFFC0000000
#elif RV_STAGE1_MODE == SATP_MODE_SV48
#define XEN_VIRT_START 0xFFFFFF8000000000
#else
#error "unsupported RV_STAGE1_MODE"
#endif

#define GAP_SIZE                MB(2)

#define XEN_VIRT_SIZE           MB(2)

#define BOOT_FDT_VIRT_START     (XEN_VIRT_START + XEN_VIRT_SIZE + GAP_SIZE)
#define BOOT_FDT_VIRT_SIZE      MB(4)

#define FIXMAP_BASE \
    (BOOT_FDT_VIRT_START + BOOT_FDT_VIRT_SIZE + GAP_SIZE)

#define DIRECTMAP_SLOT_END      509
#define DIRECTMAP_SLOT_START    200
#define DIRECTMAP_VIRT_START    SLOTN(DIRECTMAP_SLOT_START)
#define DIRECTMAP_SIZE          (SLOTN(DIRECTMAP_SLOT_END + 1) - SLOTN(DIRECTMAP_SLOT_START))
#define DIRECTMAP_VIRT_END      (DIRECTMAP_VIRT_START + DIRECTMAP_SIZE - 1)

#define FRAMETABLE_SCALE_FACTOR  (PAGE_SIZE/sizeof(struct page_info))
#define FRAMETABLE_SIZE_IN_SLOTS (((DIRECTMAP_SIZE / SLOTN(1)) / FRAMETABLE_SCALE_FACTOR) + 1)

/*
 * We have to skip Unused slot between DIRECTMAP and FRAMETABLE (look at mem.
 * layout), so -1 is needed
 */
#define FRAMETABLE_SLOT_START   (DIRECTMAP_SLOT_START - FRAMETABLE_SIZE_IN_SLOTS - 1)
#define FRAMETABLE_SIZE         (FRAMETABLE_SIZE_IN_SLOTS * SLOTN(1))
#define FRAMETABLE_VIRT_START   SLOTN(FRAMETABLE_SLOT_START)
#define FRAMETABLE_NR           (FRAMETABLE_SIZE / sizeof(*frame_table))
#define FRAMETABLE_VIRT_END     (FRAMETABLE_VIRT_START + FRAMETABLE_SIZE - 1)

/*
 * We have to skip Unused slot between Frametable and VMAP (look at mem.
 * layout), so an additional -1 is needed */
#define VMAP_SLOT_START         (FRAMETABLE_SLOT_START - 1 - 1)
#define VMAP_VIRT_START         SLOTN(VMAP_SLOT_START)
#define VMAP_VIRT_SIZE          GB(1)

#else
#error "RV32 isn't supported"
#endif

#define HYPERVISOR_VIRT_START XEN_VIRT_START

#if defined(CONFIG_RISCV_64)
# define LONG_BYTEORDER 3
# define ELFSIZE 64
# define MAX_VIRT_CPUS 128u
#else
# error "Unsupported RISCV variant"
#endif

#define BYTES_PER_LONG (1 << LONG_BYTEORDER)
#define BITS_PER_LONG  (BYTES_PER_LONG << 3)
#define POINTER_ALIGN  BYTES_PER_LONG

#define BITS_PER_LLONG 64

#define BITS_PER_BYTE 8

/* xen_ulong_t is always 64 bits */
#define BITS_PER_XEN_ULONG 64

#define CONFIG_RISCV_L1_CACHE_SHIFT 6
#define CONFIG_PAGEALLOC_MAX_ORDER  18
#define CONFIG_DOMU_MAX_ORDER       9
#define CONFIG_HWDOM_MAX_ORDER      10

#define OPT_CONSOLE_STR "dtuart"
#define INVALID_VCPU_ID MAX_VIRT_CPUS

/* Linkage for RISCV */
#ifdef __ASSEMBLY__
#define CODE_FILL /* empty */
#endif

#define SMP_CACHE_BYTES (1 << 6)

#define STACK_SIZE PAGE_SIZE

#define IDENT_AREA_SIZE 64

#ifndef __ASSEMBLY__
extern unsigned long phys_offset; /* = load_start - XEN_VIRT_START */
#endif

#endif /* ASM__RISCV__CONFIG_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
