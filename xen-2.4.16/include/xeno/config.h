/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XENO_CONFIG_H__
#define __XENO_CONFIG_H__

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
#define CONFIG_BLK_DEV_IDE_MODES 1

#define CONFIG_SCSI 1
#define CONFIG_BLK_DEV_SD 1
#define CONFIG_SD_EXTRA_DEVS 40
#define CONFIG_SCSI_MULTI_LUN 1

#define HZ 100

/* Just to keep compiler happy. */
#define SMP_CACHE_BYTES 64
#define NR_CPUS 16
#define __cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned __cacheline_aligned

/* 0-8MB is fixed monitor space for now. */
#define MAX_MONITOR_ADDRESS ( 16*1024*1024)
#define MAX_DMA_ADDRESS     ( 16*1024*1024)
#define MAX_USABLE_ADDRESS  ((0xfc000000-__PAGE_OFFSET) & ~((1<<22)-1))
                             /*^^^^^^^^^*/
                             /*arbitrary*/

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

/* syslog levels ==> nothing! */
#define KERN_NOTICE
#define KERN_WARNING
#define KERN_DEBUG
#define KERN_INFO
#define KERN_ERR
#define KERN_CRIT
#define KERN_EMERG
#define KERN_ALERT

#define barrier() __asm__ __volatile__("": : :"memory")

#define __HYPERVISOR_CS 0x30
#define __HYPERVISOR_DS 0x38
#define __GUEST_CS      0x11
#define __GUEST_DS      0x19

#define NR_syscalls 255

#define offsetof(_p,_f) ((unsigned long)&(((_p *)0)->_f))
#define struct_cpy(_x,_y) (memcpy((_x),(_y),sizeof(*(_x))))

#define likely(_x) (_x)
#define unlikely(_x) (_x)

#define dev_probe_lock() ((void)0)
#define dev_probe_unlock() ((void)0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define capable(_c) 0

#ifndef __ASSEMBLY__
extern unsigned long opt_ipbase, opt_nfsserv, opt_gateway, opt_netmask;
extern unsigned char opt_nfsroot[];
#endif

#endif /* __XENO_CONFIG_H__ */
