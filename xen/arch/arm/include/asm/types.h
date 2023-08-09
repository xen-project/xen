#ifndef __ARM_TYPES_H__
#define __ARM_TYPES_H__

#if defined(CONFIG_ARM_32)

typedef u32 vaddr_t;
#define PRIvaddr PRIx32
#if defined(CONFIG_PHYS_ADDR_T_32)

/*
 * We use "unsigned long" and not "uint32_t" to denote the type. This is done
 * to avoid having a cast each time PAGE_* macros are used on paddr_t. For eg
 * PAGE_SIZE is defined as unsigned long.
 * On 32-bit architecture, "unsigned long" is 32-bit wide. Thus, we can use it
 * to denote physical address.
 */
typedef unsigned long paddr_t;
#define INVALID_PADDR (~0UL)
#define PRIpaddr "08lx"
#else
typedef u64 paddr_t;
#define INVALID_PADDR (~0ULL)
#define PRIpaddr "016llx"
#endif
typedef u32 register_t;
#define PRIregister "08x"

#elif defined(CONFIG_ARM_64)

typedef u64 vaddr_t;
#define PRIvaddr PRIx64
typedef u64 paddr_t;
#define INVALID_PADDR (~0UL)
#define PRIpaddr "016lx"
typedef u64 register_t;
#define PRIregister "016lx"

#endif

#endif /* __ARM_TYPES_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
