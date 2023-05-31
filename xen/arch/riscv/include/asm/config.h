#ifndef __RISCV_CONFIG_H__
#define __RISCV_CONFIG_H__

#include <xen/const.h>
#include <xen/page-size.h>

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
 * ============================================================================
 *    Start addr    |   End addr        |  Size  | Slot       |area description
 * ============================================================================
 * FFFFFFFFC0800000 |  FFFFFFFFFFFFFFFF |1016 MB | L2 511     | Unused
 * FFFFFFFFC0600000 |  FFFFFFFFC0800000 |  2 MB  | L2 511     | Fixmap
 * FFFFFFFFC0200000 |  FFFFFFFFC0600000 |  4 MB  | L2 511     | FDT
 * FFFFFFFFC0000000 |  FFFFFFFFC0200000 |  2 MB  | L2 511     | Xen
 *                 ...                  |  1 GB  | L2 510     | Unused
 * 0000003200000000 |  0000007F80000000 | 309 GB | L2 200-509 | Direct map
 *                 ...                  |  1 GB  | L2 199     | Unused
 * 0000003100000000 |  00000031C0000000 |  3 GB  | L2 196-198 | Frametable
 *                 ...                  |  1 GB  | L2 195     | Unused
 * 0000003080000000 |  00000030C0000000 |  1 GB  | L2 194     | VMAP
 *                 ...                  | 194 GB | L2 0 - 193 | Unused
 * ============================================================================
 *
#endif
 */

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
#define ALIGN .align 4

#define ENTRY(name)                                \
  .globl name;                                     \
  ALIGN;                                           \
  name:
#endif

#define XEN_VIRT_START  _AT(UL, 0x80200000)

#define SMP_CACHE_BYTES (1 << 6)

#define STACK_SIZE PAGE_SIZE

#endif /* __RISCV_CONFIG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
