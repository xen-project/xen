#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <linux/thread_info.h>
#include <asm/tlb.h>
#include <asm/vmx_vpd.h>
#include <asm/vmmu.h>
#include <asm/regionreg.h>
#include <public/arch-ia64.h>
#include <asm/vmx_platform.h>
#include <xen/list.h>
#include <xen/cpumask.h>

extern void domain_relinquish_resources(struct domain *);

/* Flush cache of domain d.
   If sync_only is true, only synchronize I&D caches,
   if false, flush and invalidate caches.  */
extern void domain_cache_flush (struct domain *d, int sync_only);

/* Cleanly crash the current domain with a message.  */
extern void panic_domain(struct pt_regs *, const char *, ...)
     __attribute__ ((noreturn, format (printf, 2, 3)));

struct arch_domain {
    struct mm_struct *mm;
    unsigned long metaphysical_rr0;
    unsigned long metaphysical_rr4;

    /* There are two ranges of RID for a domain:
       one big range, used to virtualize domain RID,
       one small range for internal Xen use (metaphysical).  */
    /* Big range.  */
    int starting_rid;		/* first RID assigned to domain */
    int ending_rid;		/* one beyond highest RID assigned to domain */
    int rid_bits;		/* number of virtual rid bits (default: 18) */
    /* Metaphysical range.  */
    int starting_mp_rid;
    int ending_mp_rid;

    int breakimm;     /* The imm value for hypercalls.  */

    int physmap_built;		/* Whether is physmap built or not */
    int imp_va_msb;
    /* System pages out of guest memory, like for xenstore/console */
    unsigned long sys_pgnr;
    unsigned long max_pfn; /* Max pfn including I/O holes */
    struct virtual_platform_def     vmx_platform;
#define	hvm_domain vmx_platform /* platform defs are not vmx specific */

    u64 xen_vastart;
    u64 xen_vaend;
    u64 shared_info_va;
    unsigned long initrd_start;
    unsigned long initrd_len;
    char *cmdline;
};
#define xen_vastart arch.xen_vastart
#define xen_vaend arch.xen_vaend
#define shared_info_va arch.shared_info_va
#define INT_ENABLE_OFFSET(v) 		  \
    (sizeof(vcpu_info_t) * (v)->vcpu_id + \
    offsetof(vcpu_info_t, evtchn_upcall_mask))

struct arch_vcpu {
	TR_ENTRY itrs[NITRS];
	TR_ENTRY dtrs[NDTRS];
	TR_ENTRY itlb;
	TR_ENTRY dtlb;
	unsigned int itr_regions;
	unsigned int dtr_regions;
	unsigned long irr[4];
	unsigned long insvc[4];
	unsigned long tc_regions;
	unsigned long iva;
	unsigned long dcr;
	unsigned long itc;
	unsigned long domain_itm;
	unsigned long domain_itm_last;
	unsigned long xen_itm;

    mapped_regs_t *privregs; /* save the state of vcpu */

    /* These fields are copied from arch_domain to make access easier/faster
       in assembly code.  */
    unsigned long metaphysical_rr0;		// from arch_domain (so is pinned)
    unsigned long metaphysical_rr4;		// from arch_domain (so is pinned)
    unsigned long metaphysical_saved_rr0;	// from arch_domain (so is pinned)
    unsigned long metaphysical_saved_rr4;	// from arch_domain (so is pinned)
    int breakimm;			// from arch_domain (so is pinned)
    int starting_rid;		/* first RID assigned to domain */
    int ending_rid;		/* one beyond highest RID assigned to domain */

    struct thread_struct _thread;	// this must be last

    thash_cb_t vtlb;
    thash_cb_t vhpt;
    char irq_new_pending;
    char irq_new_condition;    // vpsr.i/vtpr change, check for pending VHPI
    char hypercall_continuation;
    //for phycial  emulation
    unsigned long old_rsc;
    int mode_flags;
    struct arch_vmx_struct arch_vmx; /* Virtual Machine Extensions */
};

//#define thread arch._thread

// FOLLOWING FROM linux-2.6.7/include/sched.h

struct mm_struct {
	pgd_t * pgd;
    //	atomic_t mm_users;			/* How many users with user space? */
	struct list_head pt_list;		/* List of pagetable */
};

extern struct mm_struct init_mm;

struct page_info * assign_new_domain_page(struct domain *d, unsigned long mpaddr);
void assign_new_domain0_page(struct domain *d, unsigned long mpaddr);
void assign_domain_page(struct domain *d, unsigned long mpaddr, unsigned long physaddr);
void assign_domain_io_page(struct domain *d, unsigned long mpaddr, unsigned long flags);
#ifdef CONFIG_XEN_IA64_DOM0_VP
unsigned long assign_domain_mmio_page(struct domain *d, unsigned long mpaddr, unsigned long size);
unsigned long assign_domain_mach_page(struct domain *d, unsigned long mpaddr, unsigned long size);
unsigned long do_dom0vp_op(unsigned long cmd, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3);
unsigned long dom0vp_populate_physmap(struct domain *d, unsigned long gpfn, unsigned int extent_order, unsigned int address_bits);
unsigned long dom0vp_zap_physmap(struct domain *d, unsigned long gpfn, unsigned int extent_order);
unsigned long dom0vp_add_physmap(struct domain* d, unsigned long gpfn, unsigned long mfn, unsigned int flags, domid_t domid);
#endif

#include <asm/uaccess.h> /* for KERNEL_DS */
#include <asm/pgtable.h>

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
