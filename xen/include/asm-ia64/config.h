// control flags for turning on/off features under test
#undef CLONE_DOMAIN0
//#define CLONE_DOMAIN0 1

// manufactured from component pieces

// defined in linux/arch/ia64/defconfig
//#define	CONFIG_IA64_GENERIC
#define	CONFIG_IA64_HP_SIM
#define	CONFIG_IA64_L1_CACHE_SHIFT 7
// needed by include/asm-ia64/page.h
#define	CONFIG_IA64_PAGE_SIZE_16KB	// 4KB doesn't work?!?
#define	CONFIG_IA64_GRANULE_16MB
// needed in arch/ia64/setup.c to reserve memory for domain0
#define CONFIG_BLK_DEV_INITRD

#ifndef __ASSEMBLY__

// can't find where this typedef was before?!?
// needed by include/asm-ia64/processor.h (and other places)
typedef int pid_t;

// from include/linux/kernel.h
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

//////////////////////////////////////

// FIXME: generated automatically into offsets.h??
#define IA64_TASK_SIZE 0 // this probably needs to be fixed
//#define IA64_TASK_SIZE sizeof(struct task_struct)

#define FASTCALL(x) x	// see linux/include/linux/linkage.h
#define fastcall	// " "

// from linux/include/linux/types.h
#define BITS_TO_LONGS(bits) \
	(((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]
#define CLEAR_BITMAP(name,bits) \
	memset(name, 0, BITS_TO_LONGS(bits)*sizeof(unsigned long))

// from linux/include/linux/compiler.h
#define __user

// FIXME?: x86-ism used in xen/mm.h
#define LOCK_PREFIX

// from linux/include/linux/mm.h
extern struct page *mem_map;

// defined in include/asm-x86/mm.h, not really used for ia64
typedef struct {
    void	(*enable)(struct domain *p);
    void	(*disable)(struct domain *p);
} vm_assist_info_t;
extern vm_assist_info_t vm_assist_info[];

// xen/include/asm/config.h
extern char _end[]; /* standard ELF symbol */

// linux/include/linux/compiler.h
#define __attribute_const__

// xen/include/asm/config.h
#define HZ 100
// leave SMP for a later time
#define NR_CPUS 1
//#define NR_CPUS 16
//#define CONFIG_NR_CPUS 16
#define barrier() __asm__ __volatile__("": : :"memory")

///////////////////////////////////////////////////////////////
// xen/include/asm/config.h
#define XENHEAP_DEFAULT_MB (16)
#define	ELFSIZE	64

///////////////////////////////////////////////////////////////

// get rid of difficult circular include dependency
#define CMPXCHG_BUGCHECK(v)
#define CMPXCHG_BUGCHECK_DECL

// from include/asm-ia64/smp.h
#ifdef CONFIG_SMP
#error "Lots of things to fix to enable CONFIG_SMP!"
#endif
#define	get_cpu()	0
#define put_cpu()	do {} while(0)

// from linux/include/linux/mm.h
struct page;

// function calls; see decl in xen/include/xen/sched.h
#undef free_task_struct
#undef alloc_task_struct

// initial task has a different name in Xen
//#define	idle0_task	init_task
#define	idle0_exec_domain	init_task

// avoid redefining task_t in asm/thread_info.h
#define task_t	struct domain

// linux/include/asm-ia64/machvec.h (linux/arch/ia64/lib/io.c)
#define platform_inb	__ia64_inb
#define platform_inw	__ia64_inw
#define platform_inl	__ia64_inl
#define platform_outb	__ia64_outb
#define platform_outw	__ia64_outw
#define platform_outl	__ia64_outl

// FIXME: This just overrides a use in a typedef (not allowed in ia64,
//  or maybe just in older gcc's?) used in ac_timer.c but should be OK
//  (and indeed is probably required!) elsewhere
#undef __cacheline_aligned
#undef ____cacheline_aligned
#undef ____cacheline_aligned_in_smp
#define __cacheline_aligned
#define ____cacheline_aligned
#define ____cacheline_aligned_in_smp

#include "asm/types.h"	// for u64
struct device {
#if 0
	struct list_head node;		/* node in sibling list */
	struct list_head bus_list;	/* node in bus's list */
	struct list_head driver_list;
	struct list_head children;
	struct device 	* parent;

	struct kobject kobj;
	char	bus_id[BUS_ID_SIZE];	/* position on parent bus */

	struct bus_type	* bus;		/* type of bus device is on */
	struct device_driver *driver;	/* which driver has allocated this
					   device */
	void		*driver_data;	/* data private to the driver */
	void		*platform_data;	/* Platform specific data (e.g. ACPI,
					   BIOS data relevant to device) */
	struct dev_pm_info	power;
	u32		power_state;	/* Current operating state. In
					   ACPI-speak, this is D0-D3, D0
					   being fully functional, and D3
					   being off. */

	unsigned char *saved_state;	/* saved device state */
	u32		detach_state;	/* State to enter when device is
					   detached from its driver. */

#endif
	u64		*dma_mask;	/* dma mask (if dma'able device) */
#if 0
	struct list_head	dma_pools;	/* dma pools (if dma'ble) */

	void	(*release)(struct device * dev);
#endif
};

// from linux/include/linux/pci.h
struct pci_bus_region {
	unsigned long start;
	unsigned long end;
};

// from linux/include/linux/module.h

// warning: unless search_extable is declared, the return value gets
// truncated to 32-bits, causing a very strange error in privop handling
struct exception_table_entry;

const struct exception_table_entry *
search_extable(const struct exception_table_entry *first,
	       const struct exception_table_entry *last,
	       unsigned long value);
void sort_extable(struct exception_table_entry *start,
		  struct exception_table_entry *finish);
void sort_main_extable(void);

// defined (why?) in include/asm-i386/processor.h
// used in common/physdev.c
#define IO_BITMAP_SIZE 32
#define IO_BITMAP_BYTES (IO_BITMAP_SIZE * 4)

#define printk printf

#define __ARCH_HAS_SLAB_ALLOCATOR  // see include/xen/slab.h
#define xmem_cache_t kmem_cache_t
#define	xmem_cache_alloc(a)	kmem_cache_alloc(a,GFP_KERNEL)
#define	xmem_cache_free(a,b)	kmem_cache_free(a,b)
#define	xmem_cache_create	kmem_cache_create
#define	xmalloc(_type)		kmalloc(sizeof(_type),GFP_KERNEL)
#define	xmalloc_array(_type,_num)	kmalloc(sizeof(_type)*_num,GFP_KERNEL)
#define	xfree(a)		kfree(a)

#undef  __ARCH_IRQ_STAT

#define find_first_set_bit(x)	(ffs(x)-1)	// FIXME: Is this right???

// from include/asm-x86/*/uaccess.h
#define array_access_ok(type,addr,count,size)                    \
    (likely(sizeof(count) <= 4) /* disallow 64-bit counts */ &&  \
     access_ok(type,addr,count*size))

// without this, uart_config_stageX does outb's which are non-portable
#define NO_UART_CONFIG_OK

// see drivers/char/console.c
#define	OPT_CONSOLE_STR "com1"

#define __attribute_used__	__attribute__ ((unused))

// see include/asm-x86/atomic.h (different from standard linux)
#define _atomic_set(v,i) (((v).counter) = (i))
#define _atomic_read(v) ((v).counter)
// FIXME following needs work
#define atomic_compareandswap(old, new, v) old

// x86 typedef still used in sched.h, may go away later
//typedef unsigned long l1_pgentry_t;

// see include/asm-ia64/mm.h, handle remaining pfn_info uses until gone
#define pfn_info page

// see common/keyhandler.c
#define	nop()	asm volatile ("nop 0")

#define ARCH_HAS_EXEC_DOMAIN_MM_PTR

// see arch/x86/nmi.c !?!?
extern unsigned int watchdog_on;

// xen/include/asm/config.h
/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XEN_IA64_CONFIG_H__
#define __XEN_IA64_CONFIG_H__

#undef CONFIG_X86

//#define CONFIG_SMP 1
//#define CONFIG_NR_CPUS 2
//leave SMP for a later time
#undef CONFIG_SMP
#undef CONFIG_X86_LOCAL_APIC
#undef CONFIG_X86_IO_APIC
#undef CONFIG_X86_L1_CACHE_SHIFT

// this needs to be on to run on hp zx1 with more than 4GB
// it is hacked around for now though
//#define	CONFIG_VIRTUAL_MEM_MAP

//#ifndef CONFIG_IA64_HP_SIM
// looks like this is hard to turn off for Xen
#define CONFIG_ACPI 1
#define CONFIG_ACPI_BOOT 1
//#endif

#define CONFIG_PCI 1
#define CONFIG_PCI_BIOS 1
#define CONFIG_PCI_DIRECT 1

#define CONFIG_XEN_ATTENTION_KEY 1
#endif /* __ASSEMBLY__ */
#endif /* __XEN_IA64_CONFIG_H__ */

// FOLLOWING ADDED FOR XEN POST-NGIO and/or LINUX 2.6.7

// following derived from linux/include/linux/compiler-gcc3.h
// problem because xen (over?)simplifies include/xen/compiler.h
#if __GNUC_MAJOR < 3 || __GNUC_MINOR__ >= 3
# define __attribute_used__	__attribute__((__used__))
#else
# define __attribute_used__	__attribute__((__unused__))
#endif
