/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __X86_CONFIG_H__
#define __X86_CONFIG_H__

#ifdef __i386__
#define CONFIG_VMX 1
#endif

#define CONFIG_X86 1

#define CONFIG_SMP 1
#define CONFIG_X86_LOCAL_APIC 1
#define CONFIG_X86_GOOD_APIC 1
#define CONFIG_X86_IO_APIC 1
#define CONFIG_X86_L1_CACHE_SHIFT 5

#define CONFIG_ACPI 1
#define CONFIG_ACPI_BOOT 1

#define CONFIG_PCI 1
#define CONFIG_PCI_DIRECT 1
#if defined(__i386__)
#define CONFIG_PCI_BIOS 1
#endif

#define CONFIG_IDE 1
#define CONFIG_BLK_DEV_IDE 1
#define CONFIG_BLK_DEV_IDEDMA 1
#define CONFIG_BLK_DEV_IDEPCI 1
#define CONFIG_IDEDISK_MULTI_MODE 1
#define CONFIG_IDEDISK_STROKE 1
#define CONFIG_IDEPCI_SHARE_IRQ 1
#define CONFIG_BLK_DEV_IDEDMA_PCI 1
#define CONFIG_IDEDMA_PCI_AUTO 1
#define CONFIG_IDEDMA_AUTO 1
#define CONFIG_IDEDMA_ONLYDISK 1
#define CONFIG_BLK_DEV_IDE_MODES 1
#define CONFIG_BLK_DEV_PIIX 1

#define CONFIG_SCSI 1
#define CONFIG_SCSI_LOGGING 1
#define CONFIG_BLK_DEV_SD 1
#define CONFIG_SD_EXTRA_DEVS 40
#define CONFIG_SCSI_MULTI_LUN 1

#define CONFIG_XEN_ATTENTION_KEY 1

#define HZ 100

#define OPT_CONSOLE_STR "com1,vga"

/*
 * Just to keep compiler happy.
 * NB. DO NOT CHANGE SMP_CACHE_BYTES WITHOUT FIXING arch/i386/entry.S!!!
 * It depends on size of irq_cpustat_t, for example, being 64 bytes. :-)
 */
#define SMP_CACHE_BYTES 64
#define NR_CPUS 16

/* Linkage for x86 */
#define __ALIGN .align 16,0x90
#define __ALIGN_STR ".align 16,0x90"
#define SYMBOL_NAME_STR(X) #X
#define SYMBOL_NAME(X) X
#define SYMBOL_NAME_LABEL(X) X##:
#ifdef __ASSEMBLY__
#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR
#define ENTRY(name) \
  .globl SYMBOL_NAME(name); \
  ALIGN; \
  SYMBOL_NAME_LABEL(name)
#endif

#define barrier() __asm__ __volatile__("": : :"memory")

#define NR_hypercalls 32

#ifndef NDEBUG
#define MEMORY_GUARD
#ifdef __x86_64__
#define STACK_ORDER 2
#endif
#endif

#ifndef STACK_ORDER
#define STACK_ORDER 1
#endif
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

#ifndef __ASSEMBLY__
extern unsigned long _end; /* standard ELF symbol */
extern void __out_of_line_bug(int line) __attribute__((noreturn));
#define out_of_line_bug() __out_of_line_bug(__LINE__)
#endif /* __ASSEMBLY__ */

#define BUG() do {					\
	printk("BUG at %s:%d\n", __FILE__, __LINE__);	\
	__asm__ __volatile__("ud2");			\
} while (0)

#if defined(__x86_64__)

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
/* Slot 257: read-only guest-accessible linear page table. */
#define RO_LINEAR_PT_VIRT_START (PML4_ADDR(257))
#define RO_LINEAR_PT_VIRT_END   (RO_LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 258: linear page table (guest table). */
#define LINEAR_PT_VIRT_START    (PML4_ADDR(258))
#define LINEAR_PT_VIRT_END      (LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 259: linear page table (shadow table). */
#define SH_LINEAR_PT_VIRT_START (PML4_ADDR(259))
#define SH_LINEAR_PT_VIRT_END   (SH_LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 260: per-domain mappings. */
#define PERDOMAIN_VIRT_START    (PML4_ADDR(260))
#define PERDOMAIN_VIRT_END      (PERDOMAIN_VIRT_START + PML4_ENTRY_BYTES)
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

#define PGT_base_page_table PGT_l4_page_table

#define __HYPERVISOR_CS64 0x0810
#define __HYPERVISOR_CS32 0x0808
#define __HYPERVISOR_CS   __HYPERVISOR_CS64
#define __HYPERVISOR_DS64 0x0000
#define __HYPERVISOR_DS32 0x0818
#define __HYPERVISOR_DS   __HYPERVISOR_DS64

#define __GUEST_CS64      0x0833
#define __GUEST_CS32      0x0823
#define __GUEST_CS        __GUEST_CS64
#define __GUEST_DS        0x0000
#define __GUEST_SS        0x082b

/* For generic assembly code: use macros to define operation/operand sizes. */
#define __OS "q"  /* Operation Suffix */
#define __OP "r"  /* Operand Prefix */

#elif defined(__i386__)

#define asmlinkage __attribute__((regparm(0)))

#define XENHEAP_DEFAULT_MB (12)
#define DIRECTMAP_PHYS_END (12*1024*1024)

/* Hypervisor owns top 64MB of virtual address space. */
#define __HYPERVISOR_VIRT_START  0xFC000000
#define HYPERVISOR_VIRT_START   (0xFC000000UL)

#define ROOT_PAGETABLE_FIRST_XEN_SLOT \
    (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT)
#define ROOT_PAGETABLE_LAST_XEN_SLOT  \
    (~0UL >> L2_PAGETABLE_SHIFT)
#define ROOT_PAGETABLE_XEN_SLOTS \
    (ROOT_PAGETABLE_LAST_XEN_SLOT - ROOT_PAGETABLE_FIRST_XEN_SLOT + 1)

/*
 * First 4MB are mapped read-only for all. It's for the machine->physical
 * mapping table (MPT table). The following are virtual addresses.
 */
#define RO_MPT_VIRT_START     (HYPERVISOR_VIRT_START)
#define RO_MPT_VIRT_END       (RO_MPT_VIRT_START + (4*1024*1024))
/* Xen heap extends to end of 1:1 direct-mapped memory region. */
#define DIRECTMAP_VIRT_START  (RO_MPT_VIRT_END)
#define DIRECTMAP_VIRT_END    (DIRECTMAP_VIRT_START + DIRECTMAP_PHYS_END)
/* Machine-to-phys conversion table. */
#define RDWR_MPT_VIRT_START   (DIRECTMAP_VIRT_END)
#define RDWR_MPT_VIRT_END     (RDWR_MPT_VIRT_START + (4*1024*1024))
/* Variable-length page-frame information array. */
#define FRAMETABLE_VIRT_START (RDWR_MPT_VIRT_END)
#define FRAMETABLE_VIRT_END   (FRAMETABLE_VIRT_START + (24*1024*1024))
/* Next 4MB of virtual address space is used as a linear p.t. mapping. */
#define LINEAR_PT_VIRT_START  (FRAMETABLE_VIRT_END)
#define LINEAR_PT_VIRT_END    (LINEAR_PT_VIRT_START + (4*1024*1024))
/* Next 4MB of virtual address space is used as a shadow linear p.t. map. */
#define SH_LINEAR_PT_VIRT_START (LINEAR_PT_VIRT_END)
#define SH_LINEAR_PT_VIRT_END (SH_LINEAR_PT_VIRT_START + (4*1024*1024))
/* Next 4MB of virtual address space used for per-domain mappings (eg. GDT). */
#define PERDOMAIN_VIRT_START  (SH_LINEAR_PT_VIRT_END)
#define PERDOMAIN_VIRT_END    (PERDOMAIN_VIRT_START + (4*1024*1024))
/* Penultimate 4MB of virtual address space used for domain page mappings. */
#define MAPCACHE_VIRT_START   (PERDOMAIN_VIRT_END)
#define MAPCACHE_VIRT_END     (MAPCACHE_VIRT_START + (4*1024*1024))
/* Final 4MB of virtual address space used for ioremap(). */
#define IOREMAP_VIRT_START    (MAPCACHE_VIRT_END)
#define IOREMAP_VIRT_END      (IOREMAP_VIRT_START + (4*1024*1024))

#define PGT_base_page_table PGT_l2_page_table

#define __HYPERVISOR_CS 0x0808
#define __HYPERVISOR_DS 0x0810

/* For generic assembly code: use macros to define operation/operand sizes. */
#define __OS "l"  /* Operation Suffix */
#define __OP "e"  /* Operand Prefix */

#endif /* __i386__ */

#ifndef __ASSEMBLY__
extern unsigned long xenheap_phys_end; /* user-configurable */
#endif

#define GDT_VIRT_START(ed)    (PERDOMAIN_VIRT_START + ((ed)->eid << PDPT_VCPU_VA_SHIFT))
#define GDT_VIRT_END(ed)      (GDT_VIRT_START(ed) + (64*1024))
#define LDT_VIRT_START(ed)    (PERDOMAIN_VIRT_START + (64*1024) + ((ed)->eid << PDPT_VCPU_VA_SHIFT))
#define LDT_VIRT_END(ed)      (LDT_VIRT_START(ed) + (64*1024))

#define PDPT_VCPU_SHIFT       5
#define PDPT_VCPU_VA_SHIFT    (PDPT_VCPU_SHIFT + PAGE_SHIFT)

#if defined(__x86_64__)
#define ELFSIZE 64
#else
#define ELFSIZE 32
#endif

#endif /* __X86_CONFIG_H__ */
