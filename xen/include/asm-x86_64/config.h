/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 * 
 */

#ifndef __XENO_X86_64_CONFIG_H__
#define __XENO_X86_64_CONFIG_H__

#define CONFIG_X86    1
#define CONFIG_X86_64BITMODE 1

#define CONFIG_SMP 1
#define CONFIG_X86_LOCAL_APIC 1
#define CONFIG_X86_IO_APIC 1
#define CONFIG_X86_L1_CACHE_SHIFT 5

#define CONFIG_PCI 1
#define CONFIG_PCI_BIOS 1
#define CONFIG_PCI_DIRECT 1

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

/*
 * Just to keep compiler happy.
 * NB. DO NOT CHANGE SMP_CACHE_BYTES WITHOUT FIXING arch/i386/entry.S!!!
 * It depends on size of irq_cpustat_t, for example, being 64 bytes. :-)
 * Mmmm... so niiiiiice....
 */
#define SMP_CACHE_BYTES 64
#define NR_CPUS 16
#define __cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned __cacheline_aligned

#define PHYSICAL_ADDRESS_BITS 52
#define MAX_PHYSICAL_ADDRESS (1 << PHYSICAL_ADDRESS_BITS)
#define VIRTUAL_ADDRESS_BITS 48
#define XEN_PAGE_SIZE 4096

#define PTE_SIZE 8
#define TOTAL_PTES (512ULL * 512 * 512 * 512)

/* next PML4 from an _END address */
#define PML4_BITS 39
#define PML4_SPACE (1ULL << PML4_BITS)

/*
 * Memory layout
 *
 *   0x0000000000000000 - 0x00007fffffffffff Guest & user apps (128TB)
 *    (Only for 32-bit guests)
 *    0x00000000fc000000 - 0x00000000fc3fffff Machine/Physical 32-bit shadow (4MB)
 *    0x00000000fc400000 - 0x00000000feffffff IO remap for 32-bit guests (44MB)
 *    0x00000000ff000000 - 0x00000000ff3fffff 32-bit PTE shadow (4MB)
 *
 *   0xffff800000000000	- 0xffff807fffffffff Linear page table (512GB)
 *   0xffff808000000000 - 0xffff80ffffffffff Reserved for shadow page table (512GB)
 *
 *   0xffff810000000000 - 0xffff82ffffffffff Xen PML4 slots 
 *    0xffff810000000000 - 0xffff81003fffffff Xen hypervisor virtual space (1GB)
 *    0xffff810040000000 - 0xffff81807fffffff Per-domain mappings (1GB)
 *    0xffff810080000000 - 0xffff81387fffffff R/O physical map (224GB)
 *    0xffff813880000000 - 0xffff81707fffffff R/W physical map (224GB)
 *    0xffff817080000000 - 0xffff82c07fffffff Frame table (1344GB) 
 *    0xffff82c080000000 - 0xffff82c0bfffffff I/O remap space (1GB)
 *    0xffff82c0c0000000 - 0xffff82ffffffffff (253GB)
 *
 *   0xffff830000000000 - 0xffff87ffffffffff RESERVED (5TB)
 *
 *   0xffff880000000000 - ...                Physical 1:1 direct mapping (112TB max)
 *    0xffff880000000000 - 0xffff880001000000 Low memory DMA region (16M)
 *
 *   0xfffff80000000000 - 0xffffffffffffffff Reserved for guest (8TB)
 * 
 * The requirement that we have a 1:1 map of physical memory limits
 * the maximum memory size we can support.  With only 48 virtual address
 * bits, and the assumption that guests will run users in positive address
 * space, a contiguous 1:1 map can only live in the negative address space.
 * Since we don't want to bump guests out of the very top of memory and
 * force relocation, we can't use this entire space, and Xen has several
 * heavy mapping that require PML4 slices.  Just to be safe, we reserve
 * 16 PML4s each for Xen and the guest.  224 PML4s give us 112 terabytes
 * of addressable memory.  Any high device physical addresses beyond this
 * region can be mapped into the IO remap space or some of the reserved 
 * 6TB region.
 * 
 * 112 TB is just 16 TB shy of the maximum physical memory supported
 * on Linux 2.6.0, and should be enough for anybody.
 *
 * There are some additional constraints in the memory layout that require
 * several changes from the i386 architecture.
 *
 * ACPI data and ACPI non-volatile storage must be placed in some region
 * of memory below the 4GB mark.  Depending on the BIOS and system, we
 * may have this located as low as 1GB.  This means allocating large
 * chunks of physically contiguous memory from the direct mapping may not
 * be possible. 
 *
 * The full frame table for 112TB of physical memory currently occupies
 * 1344GB space.  This clearly can not be allocated in physically contiguous
 * space, so it must be moved to a virtual address.
 *
 * Both copies of the machine->physical table must also be relocated.  
 * (112 TB / 4k) * 8 bytes means that each copy of the physical map requires
 * 224GB of space, thus it also must move to VM space.
 *
 * The physical pages used to allocate the page tables for the direct 1:1
 * map may occupy (112TB / 2M) * 8 bytes = 448MB.  This is almost guaranteed
 * to fit in contiguous physical memory, but these pages used to be allocated
 * in the Xen monitor address space.  This means the Xen address space must
 * accomodate up to ~500 MB, which means it also must move out of the
 * direct mapped region. 
 *
 * Since both copies of the MPT, the frame table, and Xen now exist in
 * purely virtual space, we have the added advantage of being able to
 * map them to local pages on NUMA machines, or use NUMA aware memory
 * allocation within Xen itself.
 *
 * Additionally, the 1:1 page table now exists contiguously in virtual
 * space, but may be mapped to physically separated pages, allowing
 * each node to contain the page tables for its own local memory.  Setting
 * up this mapping presents a bit of a chicken-egg problem, but is possible
 * as a future enhancement. 
 *
 * Zachary Amsden (zamsden@cisco.com)
 *
 */

/* Guest and user space */
#define NSPACE_VIRT_START	0
#define NSPACE_VIRT_END		(1ULL << (VIRTUAL_ADDRESS_BITS - 1))

/* Priviledged space */
#define ESPACE_VIRT_END		0
#define ESPACE_VIRT_START	(ESPACE_VIRT_END-(1ULL << (VIRTUAL_ADDRESS_BITS-1)))

/* reservations in e-space */
#define GUEST_RESERVED_PML4S 16
#define XEN_RESERVED_PML4S 16

#define MAX_MEMORY_SIZE ((1ULL << (VIRTUAL_ADDRESS_BITS-1)) \
			-((GUEST_RESERVED_PML4S + XEN_RESERVED_PML4S) * PML4_SPACE))
#define MAX_MEMORY_FRAMES (MAX_MEMORY_SIZE / XEN_PAGE_SIZE)

/*
 * Virtual addresses beyond this are not modifiable by guest OSes. 
 */
#define HYPERVISOR_VIRT_START ESPACE_VIRT_START
#define HYPERVISOR_VIRT_END   (ESPACE_VIRT_END-(GUEST_RESERVED_PML4S * PML4_SPACE))

/* First 512GB of virtual address space is used as a linear p.t. mapping. */
#define LINEAR_PT_VIRT_START  (HYPERVISOR_VIRT_START)
#define LINEAR_PT_VIRT_END    (LINEAR_PT_VIRT_START + (PTE_SIZE * TOTAL_PTES))

/* Reserve some space for a shadow PT mapping */
#define SHADOW_PT_VIRT_START  (LINEAR_PT_VIRT_END)
#define SHADOW_PT_VIRT_END    (SHADOW_PT_VIRT_START + (PTE_SIZE * TOTAL_PTES))

/* Xen exists in the first 1GB of the next PML4 space */
#define MAX_MONITOR_ADDRESS   (1 * 1024 * 1024 * 1024)
#define MONITOR_VIRT_START    (SHADOW_PT_VIRT_END)
#define MONITOR_VIRT_END      (MONITOR_VIRT_START + MAX_MONITOR_ADDRESS)

/* Next 1GB of virtual address space used for per-domain mappings (eg. GDT). */
#define PERDOMAIN_VIRT_START  (MONITOR_VIRT_END)
#define PERDOMAIN_VIRT_END    (PERDOMAIN_VIRT_START + (512 * 512 * 4096))
#define GDT_VIRT_START        (PERDOMAIN_VIRT_START)
#define GDT_VIRT_END          (GDT_VIRT_START + (128*1024))
#define LDT_VIRT_START        (GDT_VIRT_END)
#define LDT_VIRT_END          (LDT_VIRT_START + (128*1024))

/*
 * First set of MPTs are mapped read-only for all. It's for the machine->physical
 * mapping table (MPT table). The following are virtual addresses.
 */
#define READONLY_MPT_VIRT_START (PERDOMAIN_VIRT_END)
#define READONLY_MPT_VIRT_END   (READONLY_MPT_VIRT_START + (PTE_SIZE * MAX_MEMORY_FRAMES))

/* R/W machine->physical table */
#define RDWR_MPT_VIRT_START   (READONLY_MPT_VIRT_END)
#define RDWR_MPT_VIRT_END     (RDWR_MPT_VIRT_START + (PTE_SIZE * MAX_MEMORY_FRAMES))

/* Frame table */
#define FRAMETABLE_ENTRY_SIZE	(48)
#define FRAMETABLE_VIRT_START (RDWR_MPT_VIRT_END)
#define FRAMETABLE_VIRT_END   (FRAMETABLE_VIRT_START + (FRAMETABLE_ENTRY_SIZE * MAX_MEMORY_FRAMES))

/* Next 1GB of virtual address space used for ioremap(). */
#define IOREMAP_VIRT_START    (FRAMETABLE_VIRT_END)
#define IOREMAP_VIRT_END      (IOREMAP_VIRT_START + (512 * 512 * 4096))

/* And the virtual addresses for the direct-map region... */
#define DIRECTMAP_VIRT_START  (ESPACE_VIRT_START + (XEN_RESERVED_PML4S * PML4_SPACE))
#define DIRECTMAP_VIRT_END    (DIRECTMAP_VIRT_START + MAX_DIRECTMAP_ADDRESS)

/*
 * Next is the direct-mapped memory region. The following are machine addresses.
 */
#define MAX_DMA_ADDRESS       (16*1024*1024)
#define MAX_DIRECTMAP_ADDRESS MAX_MEMORY_SIZE



/*
 * Amount of slack domain memory to leave in system, in kilobytes.
 * Prevents a hard out-of-memory crunch for thinsg like network receive.
 */
#define SLACK_DOMAIN_MEM_KILOBYTES 2048


/*
 * These will probably change in the future..
 * locations for 32-bit guest compatibility mappings
 */

/* 4M of 32-bit machine-physical shadow in low 4G of VM space */
#define SHADOW_MPT32_VIRT_START (0xfc000000)
#define SHADOW_MPT32_VIRT_END   (SHADOW_MPT32_VIRT_START + (4 * 1024 * 1024))

/* 44M of I/O remap for 32-bit drivers */
#define IOREMAP_LOW_VIRT_START (SHADOW_MPT32_VIRT_END)
#define IOREMAP_LOW_VIRT_END   (IOREMAP_LOW_VIRT_START + (44 * 1024 * 1024))

/* 4M of 32-bit page table */
#define SHADOW_PT32_VIRT_START (IOREMAP_LOW_VIRT_END)
#define SHADOW_PT32_VIRT_END   (SHADOW_PT32_VIRT_START + (4 * 1024 * 1024))


/* Linkage for x86 */
#define FASTCALL(x)     x __attribute__((regparm(3)))
#define asmlinkage        __attribute__((regparm(0)))
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

#define PGT_base_page_table PGT_l4_page_table

#define barrier() __asm__ __volatile__("": : :"memory")

/*
 * Hypervisor segment selectors
 */
#define __HYPERVISOR_CS64 0x0810
#define __HYPERVISOR_CS32 0x0808
#define __HYPERVISOR_DS 0x0818

#define NR_syscalls 256

#ifndef NDEBUG
#define MEMORY_GUARD
#define TRACE_BUFFER
#endif

#ifndef __ASSEMBLY__
extern unsigned long _end; /* standard ELF symbol */
extern void __out_of_line_bug(int line) __attribute__((noreturn));
#define out_of_line_bug() __out_of_line_bug(__LINE__)
#endif /* __ASSEMBLY__ */

#endif /* __XENO_X86_64_CONFIG_H__ */
