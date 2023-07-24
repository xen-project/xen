#ifndef __PPC_CONFIG_H__
#define __PPC_CONFIG_H__

#include <xen/const.h>
#include <xen/page-size.h>

#if defined(CONFIG_PPC64)
#define LONG_BYTEORDER 3
#define ELFSIZE        64
#define MAX_VIRT_CPUS  1024u
#else
#error "Unsupported PowerPC variant"
#endif

#define BYTES_PER_LONG (1 << LONG_BYTEORDER)
#define BITS_PER_LONG  (BYTES_PER_LONG << 3)
#define POINTER_ALIGN  BYTES_PER_LONG

#define BITS_PER_LLONG 64

/* xen_ulong_t is always 64 bits */
#define BITS_PER_XEN_ULONG 64

#define CONFIG_PPC_L1_CACHE_SHIFT  7
#define CONFIG_PAGEALLOC_MAX_ORDER 18
#define CONFIG_DOMU_MAX_ORDER      9
#define CONFIG_HWDOM_MAX_ORDER     10

#define OPT_CONSOLE_STR "dtuart"
#define INVALID_VCPU_ID MAX_VIRT_CPUS

/* Linkage for PPC */
#ifdef __ASSEMBLY__
#define ALIGN .p2align 2

#define ENTRY(name)                                                            \
    .globl name;                                                               \
    ALIGN;                                                                     \
    name:
#endif

#define XEN_VIRT_START _AT(UL, 0x400000)

#define SMP_CACHE_BYTES (1 << 6)

#define STACK_ORDER 0
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

/* 288 bytes below the stack pointer must be preserved by interrupt handlers */
#define STACK_VOLATILE_AREA 288

/* size of minimum stack frame; C code can write into the caller's stack */
#define STACK_FRAME_OVERHEAD 32

#endif /* __PPC_CONFIG_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
