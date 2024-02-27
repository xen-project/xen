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
#define ALIGN .balign CONFIG_FUNCTION_ALIGNMENT
#define ENTRY(name)                             \
  .globl name;                                  \
  ALIGN;                                        \
  name:
#define GLOBAL(name)                            \
  .globl name;                                  \
  name:
#define ENDPROC(name) \
  .type name, %function; \
  END(name)
#endif

#include <xen/const.h>
#include <xen/page-size.h>

#ifdef CONFIG_MMU
#include <asm/mmu/layout.h>
#else
# error "Unknown memory management layout"
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
