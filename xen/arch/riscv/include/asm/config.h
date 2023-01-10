#ifndef __RISCV_CONFIG_H__
#define __RISCV_CONFIG_H__

#include <xen/const.h>
#include <xen/page-size.h>

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
