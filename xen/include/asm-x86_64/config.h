/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XENO_X86_64_CONFIG_H__
#define __XENO_X86_64_CONFIG_H__

#define CONFIG_X86 1

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

/*
 * Virtual addresses beyond this are not modifiable by guest OSes. The
 * machine->physical mapping table starts at this address, read-only.
 */
#define HYPERVISOR_VIRT_START (0xFFFF800000000000ULL)
                                                                                                
/*
 * Xen exists in the highest 2GB of address space for RIP-relative
 * addressing
 */
#define XEN_VIRT_START        (0xFFFFFFFF80000000ULL)
                                                                                                
/*
 * First 4MB are mapped read-only for all. It's for the machine->physical
 * mapping table (MPT table). The following are virtual addresses.
 */
#define READONLY_MPT_VIRT_START (HYPERVISOR_VIRT_START)
#define READONLY_MPT_VIRT_END   (READONLY_MPT_VIRT_START + (4*1024*1024))
/*
 * Next 16MB is fixed monitor space, which is part of a 44MB direct-mapped
 * memory region. The following are machine addresses.
 */
#define MAX_MONITOR_ADDRESS   (16*1024*1024)
#define MAX_DMA_ADDRESS       (16*1024*1024)
#define MAX_DIRECTMAP_ADDRESS (44*1024*1024)
/* And the virtual addresses for the direct-map region... */
#define DIRECTMAP_VIRT_START  (READONLY_MPT_VIRT_END)
#define DIRECTMAP_VIRT_END    (DIRECTMAP_VIRT_START + MAX_DIRECTMAP_ADDRESS)
#define MONITOR_VIRT_START    (DIRECTMAP_VIRT_START)
#define MONITOR_VIRT_END      (MONITOR_VIRT_START + MAX_MONITOR_ADDRESS)
#define RDWR_MPT_VIRT_START   (MONITOR_VIRT_END)
#define RDWR_MPT_VIRT_END     (RDWR_MPT_VIRT_START + (4*1024*1024))
#define FRAMETABLE_VIRT_START (RDWR_MPT_VIRT_END)
#define FRAMETABLE_VIRT_END   (DIRECTMAP_VIRT_END)
/* Next 4MB of virtual address space is used as a linear p.t. mapping. */
#define LINEAR_PT_VIRT_START  (DIRECTMAP_VIRT_END)
#define LINEAR_PT_VIRT_END    (LINEAR_PT_VIRT_START + (4*1024*1024))
/* Next 4MB of virtual address space used for per-domain mappings (eg. GDT). */
#define PERDOMAIN_VIRT_START  (LINEAR_PT_VIRT_END)
#define PERDOMAIN_VIRT_END    (PERDOMAIN_VIRT_START + (4*1024*1024))
#define GDT_VIRT_START        (PERDOMAIN_VIRT_START)
#define GDT_VIRT_END          (GDT_VIRT_START + (64*1024))
#define LDT_VIRT_START        (GDT_VIRT_END)
#define LDT_VIRT_END          (LDT_VIRT_START + (64*1024))
/* Penultimate 4MB of virtual address space used for domain page mappings. */
#define MAPCACHE_VIRT_START   (PERDOMAIN_VIRT_END)
#define MAPCACHE_VIRT_END     (MAPCACHE_VIRT_START + (4*1024*1024))
/* Final 4MB of virtual address space used for ioremap(). */
#define IOREMAP_VIRT_START    (MAPCACHE_VIRT_END)
#define IOREMAP_VIRT_END      (IOREMAP_VIRT_START + (4*1024*1024))

/*
 * Amount of slack domain memory to leave in system, in megabytes.
 * Prevents a hard out-of-memory crunch for thinsg like network receive.
 */
#define SLACK_DOMAIN_MEM_KILOBYTES 2048

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
