/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __X86_CONFIG_H__
#define __X86_CONFIG_H__

#if defined(__x86_64__)
# define CONFIG_PAGING_LEVELS 4
#elif defined(CONFIG_X86_PAE)
# define CONFIG_PAGING_LEVELS 3
#else
# define CONFIG_PAGING_LEVELS 2
#endif

#define CONFIG_X86 1
#define CONFIG_X86_HT 1
#define CONFIG_SHADOW 1
#define CONFIG_SMP 1
#define CONFIG_X86_LOCAL_APIC 1
#define CONFIG_X86_GOOD_APIC 1
#define CONFIG_X86_IO_APIC 1
#define CONFIG_HPET_TIMER 1
#define CONFIG_X86_MCE_P4THERMAL 1

/* Intel P4 currently has largest cache line (L2 line size is 128 bytes). */
#define CONFIG_X86_L1_CACHE_SHIFT 7

#define CONFIG_ACPI 1
#define CONFIG_ACPI_BOOT 1

#define CONFIG_VGA 1

#define HZ 100

#define OPT_CONSOLE_STR "com1,vga"

#ifdef MAX_PHYS_CPUS
#define NR_CPUS MAX_PHYS_CPUS
#else
#define NR_CPUS 32
#endif

#if defined(__i386__) && (NR_CPUS > 32)
#error "Maximum of 32 physical processors supported by Xen on x86_32"
#endif

#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
# define supervisor_mode_kernel (1)
#else
# define supervisor_mode_kernel (0)
#endif

/* Linkage for x86 */
#define __ALIGN .align 16,0x90
#define __ALIGN_STR ".align 16,0x90"
#ifdef __ASSEMBLY__
#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR
#define ENTRY(name)                             \
  .globl name;                                  \
  ALIGN;                                        \
  name:
#endif

#define NR_hypercalls 64

#ifndef NDEBUG
#define MEMORY_GUARD
#endif

#define STACK_ORDER 2
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

/* Debug stack is restricted to 8kB by guard pages. */
#define DEBUG_STACK_SIZE 8192

#define MAX_DMADOM_PFN 0x7FFFFUL /* 31 addressable bits */

#ifndef __ASSEMBLY__
extern unsigned long _end; /* standard ELF symbol */

static inline void FORCE_CRASH(void) __attribute__((noreturn,always_inline)); 
static inline void FORCE_CRASH(void) 
{
    __asm__ __volatile__ ( "ud2" );
    while(1);
}
#endif /* __ASSEMBLY__ */

#if defined(__x86_64__)

#define CONFIG_X86_64 1

#define asmlinkage

#define XENHEAP_DEFAULT_MB (16)

#define PML4_ENTRY_BITS  39
#ifndef __ASSEMBLY__
#define PML4_ENTRY_BYTES (1UL << PML4_ENTRY_BITS)
#define PML4_ADDR(_slot)                             \
    ((((_slot ## UL) >> 8) * 0xffff000000000000UL) | \
     (_slot ## UL << PML4_ENTRY_BITS))
#else
#define PML4_ENTRY_BYTES (1 << PML4_ENTRY_BITS)
#define PML4_ADDR(_slot)                             \
    (((_slot >> 8) * 0xffff000000000000) | (_slot << PML4_ENTRY_BITS))
#endif

/*
 * Memory layout:
 *  0x0000000000000000 - 0x00007fffffffffff [128TB, 2^47 bytes, PML4:0-255]
 *    Guest-defined use.
 *  0x0000800000000000 - 0xffff7fffffffffff [16EB]
 *    Inaccessible: current arch only supports 48-bit sign-extended VAs.
 *  0xffff800000000000 - 0xffff803fffffffff [256GB, 2^38 bytes, PML4:256]
 *    Read-only machine-to-phys translation table (GUEST ACCESSIBLE).
 *  0xffff804000000000 - 0xffff807fffffffff [256GB, 2^38 bytes, PML4:256]
 *    Reserved for future shared info with the guest OS (GUEST ACCESSIBLE).
 *  0xffff808000000000 - 0xffff80ffffffffff [512GB, 2^39 bytes, PML4:257]
 *    Read-only guest linear page table (GUEST ACCESSIBLE).
 *  0xffff810000000000 - 0xffff817fffffffff [512GB, 2^39 bytes, PML4:258]
 *    Guest linear page table.
 *  0xffff818000000000 - 0xffff81ffffffffff [512GB, 2^39 bytes, PML4:259]
 *    Shadow linear page table.
 *  0xffff820000000000 - 0xffff827fffffffff [512GB, 2^39 bytes, PML4:260]
 *    Per-domain mappings (e.g., GDT, LDT).
 *  0xffff828000000000 - 0xffff8283ffffffff [16GB,  2^34 bytes, PML4:261]
 *    Machine-to-phys translation table.
 *  0xffff828400000000 - 0xffff8287ffffffff [16GB,  2^34 bytes, PML4:261]
 *    Page-frame information array.
 *  0xffff828800000000 - 0xffff828bffffffff [16GB,  2^34 bytes, PML4:261]
 *    ioremap()/fixmap area.
 *  0xffff828c00000000 - 0xffff82ffffffffff [464GB,             PML4:261]
 *    Reserved for future use.
 *  0xffff830000000000 - 0xffff83ffffffffff [1TB,   2^40 bytes, PML4:262-263]
 *    1:1 direct mapping of all physical memory. Xen and its heap live here.
 *  0xffff840000000000 - 0xffff87ffffffffff [4TB,   2^42 bytes, PML4:264-271]
 *    Reserved for future use.
 *  0xffff880000000000 - 0xffffffffffffffff [120TB, PML4:272-511]
 *    Guest-defined use.
 */


#define ROOT_PAGETABLE_FIRST_XEN_SLOT 256
#define ROOT_PAGETABLE_LAST_XEN_SLOT  271
#define ROOT_PAGETABLE_XEN_SLOTS \
    (ROOT_PAGETABLE_LAST_XEN_SLOT - ROOT_PAGETABLE_FIRST_XEN_SLOT + 1)

/* Hypervisor reserves PML4 slots 256 to 271 inclusive. */
#define HYPERVISOR_VIRT_START   (PML4_ADDR(256))
#define HYPERVISOR_VIRT_END     (HYPERVISOR_VIRT_START + PML4_ENTRY_BYTES*16)
/* Slot 256: read-only guest-accessible machine-to-phys translation table. */
#define RO_MPT_VIRT_START       (PML4_ADDR(256))
#define RO_MPT_VIRT_END         (RO_MPT_VIRT_START + PML4_ENTRY_BYTES/2)

// current unused?
#if 0
/* Slot 257: read-only guest-accessible linear page table. */
#define RO_LINEAR_PT_VIRT_START (PML4_ADDR(257))
#define RO_LINEAR_PT_VIRT_END   (RO_LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
#endif

/* Slot 258: linear page table (guest table). */
#define LINEAR_PT_VIRT_START    (PML4_ADDR(258))
#define LINEAR_PT_VIRT_END      (LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 259: linear page table (shadow table). */
#define SH_LINEAR_PT_VIRT_START (PML4_ADDR(259))
#define SH_LINEAR_PT_VIRT_END   (SH_LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 260: per-domain mappings. */
#define PERDOMAIN_VIRT_START    (PML4_ADDR(260))
#define PERDOMAIN_VIRT_END      (PERDOMAIN_VIRT_START + (PERDOMAIN_MBYTES<<20))
#define PERDOMAIN_MBYTES        ((unsigned long)GDT_LDT_MBYTES)
/* Slot 261: machine-to-phys conversion table (16GB). */
#define RDWR_MPT_VIRT_START     (PML4_ADDR(261))
#define RDWR_MPT_VIRT_END       (RDWR_MPT_VIRT_START + (16UL<<30))
/* Slot 261: page-frame information array (16GB). */
#define FRAMETABLE_VIRT_START   (RDWR_MPT_VIRT_END)
#define FRAMETABLE_VIRT_END     (FRAMETABLE_VIRT_START + (16UL<<30))
/* Slot 261: ioremap()/fixmap area (16GB). */
#define IOREMAP_VIRT_START      (FRAMETABLE_VIRT_END)
#define IOREMAP_VIRT_END        (IOREMAP_VIRT_START + (16UL<<30))
/* Slot 262-263: A direct 1:1 mapping of all of physical memory. */
#define DIRECTMAP_VIRT_START    (PML4_ADDR(262))
#define DIRECTMAP_VIRT_END      (DIRECTMAP_VIRT_START + PML4_ENTRY_BYTES*2)

#define PGT_base_page_table     PGT_l4_page_table

#define __HYPERVISOR_CS64 0xe010
#define __HYPERVISOR_CS32 0xe008
#define __HYPERVISOR_CS   __HYPERVISOR_CS64
#define __HYPERVISOR_DS64 0x0000
#define __HYPERVISOR_DS32 0xe018
#define __HYPERVISOR_DS   __HYPERVISOR_DS64

#define __GUEST_CS64      0xe033
#define __GUEST_CS32      0xe023
#define __GUEST_CS        __GUEST_CS64
#define __GUEST_DS        0x0000
#define __GUEST_SS        0xe02b

/* For generic assembly code: use macros to define operation/operand sizes. */
#define __OS          "q"  /* Operation Suffix */
#define __OP          "r"  /* Operand Prefix */
#define __FIXUP_ALIGN ".align 8"
#define __FIXUP_WORD  ".quad"

#elif defined(__i386__)

#define CONFIG_X86_32      1
#define CONFIG_DOMAIN_PAGE 1

#define asmlinkage __attribute__((regparm(0)))

/*
 * Memory layout (high to low):                          SIZE   PAE-SIZE
 *                                                       ------ ------
 *  I/O remapping area                                   ( 4MB)
 *  Direct-map (1:1) area [Xen code/data/heap]           (12MB)
 *  Per-domain mappings (inc. 4MB map_domain_page cache) ( 8MB)
 *  Shadow linear pagetable                              ( 4MB) ( 8MB)
 *  Guest linear pagetable                               ( 4MB) ( 8MB)
 *  Machine-to-physical translation table [writable]     ( 4MB) (16MB)
 *  Frame-info table                                     (24MB) (96MB)
 *   * Start of guest inaccessible area
 *  Machine-to-physical translation table [read-only]    ( 4MB) (16MB)
 *   * Start of guest unmodifiable area
 */

#define IOREMAP_MBYTES           4
#define DIRECTMAP_MBYTES        12
#define MAPCACHE_MBYTES          4
#define PERDOMAIN_MBYTES         8

#ifdef CONFIG_X86_PAE
# define LINEARPT_MBYTES         8
# define MACHPHYS_MBYTES        16 /* 1 MB needed per 1 GB memory */
# define FRAMETABLE_MBYTES (MACHPHYS_MBYTES * 6)
#else
# define LINEARPT_MBYTES         4
# define MACHPHYS_MBYTES         4
# define FRAMETABLE_MBYTES      24
#endif

#define IOREMAP_VIRT_END	0UL
#define IOREMAP_VIRT_START	(IOREMAP_VIRT_END - (IOREMAP_MBYTES<<20))
#define DIRECTMAP_VIRT_END	IOREMAP_VIRT_START
#define DIRECTMAP_VIRT_START	(DIRECTMAP_VIRT_END - (DIRECTMAP_MBYTES<<20))
#define MAPCACHE_VIRT_END	DIRECTMAP_VIRT_START
#define MAPCACHE_VIRT_START	(MAPCACHE_VIRT_END - (MAPCACHE_MBYTES<<20))
#define PERDOMAIN_VIRT_END	DIRECTMAP_VIRT_START
#define PERDOMAIN_VIRT_START	(PERDOMAIN_VIRT_END - (PERDOMAIN_MBYTES<<20))
#define SH_LINEAR_PT_VIRT_END	PERDOMAIN_VIRT_START
#define SH_LINEAR_PT_VIRT_START	(SH_LINEAR_PT_VIRT_END - (LINEARPT_MBYTES<<20))
#define LINEAR_PT_VIRT_END	SH_LINEAR_PT_VIRT_START
#define LINEAR_PT_VIRT_START	(LINEAR_PT_VIRT_END - (LINEARPT_MBYTES<<20))
#define RDWR_MPT_VIRT_END	LINEAR_PT_VIRT_START
#define RDWR_MPT_VIRT_START	(RDWR_MPT_VIRT_END - (MACHPHYS_MBYTES<<20))
#define FRAMETABLE_VIRT_END	RDWR_MPT_VIRT_START
#define FRAMETABLE_VIRT_START	(FRAMETABLE_VIRT_END - (FRAMETABLE_MBYTES<<20))
#define RO_MPT_VIRT_END		FRAMETABLE_VIRT_START
#define RO_MPT_VIRT_START	(RO_MPT_VIRT_END - (MACHPHYS_MBYTES<<20))

#define XENHEAP_DEFAULT_MB	(DIRECTMAP_MBYTES)
#define DIRECTMAP_PHYS_END	(DIRECTMAP_MBYTES<<20)

/* Maximum linear address accessible via guest memory segments. */
#define GUEST_SEGMENT_MAX_ADDR  RO_MPT_VIRT_END

#ifdef CONFIG_X86_PAE
/* Hypervisor owns top 168MB of virtual address space. */
#define HYPERVISOR_VIRT_START   mk_unsigned_long(0xF5800000)
#else
/* Hypervisor owns top 64MB of virtual address space. */
#define HYPERVISOR_VIRT_START   mk_unsigned_long(0xFC000000)
#endif

#define L2_PAGETABLE_FIRST_XEN_SLOT \
    (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT)
#define L2_PAGETABLE_LAST_XEN_SLOT  \
    (~0UL >> L2_PAGETABLE_SHIFT)
#define L2_PAGETABLE_XEN_SLOTS \
    (L2_PAGETABLE_LAST_XEN_SLOT - L2_PAGETABLE_FIRST_XEN_SLOT + 1)

#ifdef CONFIG_X86_PAE
# define PGT_base_page_table     PGT_l3_page_table
#else
# define PGT_base_page_table     PGT_l2_page_table
#endif

#define __HYPERVISOR_CS 0xe008
#define __HYPERVISOR_DS 0xe010

/* For generic assembly code: use macros to define operation/operand sizes. */
#define __OS          "l"  /* Operation Suffix */
#define __OP          "e"  /* Operand Prefix */
#define __FIXUP_ALIGN ".align 4"
#define __FIXUP_WORD  ".long"

#endif /* __i386__ */

#ifndef __ASSEMBLY__
extern unsigned long xenheap_phys_end; /* user-configurable */
#endif

/* GDT/LDT shadow mapping area. The first per-domain-mapping sub-area. */
#define GDT_LDT_VCPU_SHIFT       5
#define GDT_LDT_VCPU_VA_SHIFT    (GDT_LDT_VCPU_SHIFT + PAGE_SHIFT)
#define GDT_LDT_MBYTES           (MAX_VIRT_CPUS >> (20-GDT_LDT_VCPU_VA_SHIFT))
#define GDT_LDT_VIRT_START       PERDOMAIN_VIRT_START
#define GDT_LDT_VIRT_END         (GDT_LDT_VIRT_START + (GDT_LDT_MBYTES << 20))

/* The address of a particular VCPU's GDT or LDT. */
#define GDT_VIRT_START(v)    \
    (PERDOMAIN_VIRT_START + ((v)->vcpu_id << GDT_LDT_VCPU_VA_SHIFT))
#define LDT_VIRT_START(v)    \
    (GDT_VIRT_START(v) + (64*1024))

#define PDPT_L1_ENTRIES       \
    ((PERDOMAIN_VIRT_END - PERDOMAIN_VIRT_START) >> PAGE_SHIFT)
#define PDPT_L2_ENTRIES       \
    ((PDPT_L1_ENTRIES + (1 << PAGETABLE_ORDER) - 1) >> PAGETABLE_ORDER)

#if defined(__x86_64__)
#define ELFSIZE 64
#else
#define ELFSIZE 32
#endif

#endif /* __X86_CONFIG_H__ */
