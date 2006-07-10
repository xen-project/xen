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
#include <asm/fpswa.h>

struct p2m_entry {
    volatile pte_t*     pte;
    pte_t               used;
};

static inline void
p2m_entry_set(struct p2m_entry* entry, volatile pte_t* pte, pte_t used)
{
    entry->pte  = pte;
    entry->used = used;
}

static inline int
p2m_entry_retry(struct p2m_entry* entry)
{
    //XXX see lookup_domain_pte().
    //    NULL is set for invalid gpaddr for the time being.
    if (entry->pte == NULL)
        return 0;

    return (pte_val(*entry->pte) != pte_val(entry->used));
}

extern void domain_relinquish_resources(struct domain *);

/* given a current domain metaphysical address, return the physical address */
extern unsigned long translate_domain_mpaddr(unsigned long mpaddr,
                                             struct p2m_entry* entry);

/* Set shared_info virtual address.  */
extern unsigned long domain_set_shared_info_va (unsigned long va);

/* Flush cache of domain d.
   If sync_only is true, only synchronize I&D caches,
   if false, flush and invalidate caches.  */
extern void domain_cache_flush (struct domain *d, int sync_only);

/* Cleanly crash the current domain with a message.  */
extern void panic_domain(struct pt_regs *, const char *, ...)
     __attribute__ ((noreturn, format (printf, 2, 3)));

struct mm_struct {
	pgd_t * pgd;
    //	atomic_t mm_users;			/* How many users with user space? */
};

struct last_vcpu {
#define INVALID_VCPU_ID INT_MAX
    int vcpu_id;
} ____cacheline_aligned_in_smp;

/* These are data in domain memory for SAL emulator.  */
struct xen_sal_data {
    /* OS boot rendez vous.  */
    unsigned long boot_rdv_ip;
    unsigned long boot_rdv_r1;

    /* There are these for EFI_SET_VIRTUAL_ADDRESS_MAP emulation. */
    int efi_virt_mode;		/* phys : 0 , virt : 1 */
};

struct arch_domain {
    struct mm_struct mm;

    /* Flags.  */
    union {
        unsigned long flags;
        struct {
            unsigned int is_vti : 1;
        };
    };

    /* There are two ranges of RID for a domain:
       one big range, used to virtualize domain RID,
       one small range for internal Xen use (metaphysical).  */
    /* Big range.  */
    int starting_rid;		/* first RID assigned to domain */
    int ending_rid;		/* one beyond highest RID assigned to domain */
    /* Metaphysical range.  */
    int starting_mp_rid;
    int ending_mp_rid;
    /* RID for metaphysical mode.  */
    unsigned long metaphysical_rr0;
    unsigned long metaphysical_rr4;
    
    int rid_bits;		/* number of virtual rid bits (default: 18) */
    int breakimm;     /* The imm value for hypercalls.  */

    struct virtual_platform_def     vmx_platform;
#define	hvm_domain vmx_platform /* platform defs are not vmx specific */

    u64 xen_vastart;
    u64 xen_vaend;
    u64 shared_info_va;
 
    /* Address of SAL emulator data  */
    struct xen_sal_data *sal_data;
    /* SAL return point.  */
    unsigned long sal_return_addr;

    /* Address of efi_runtime_services_t (placed in domain memory)  */
    void *efi_runtime;
    /* Address of fpswa_interface_t (placed in domain memory)  */
    void *fpswa_inf;

    struct last_vcpu last_vcpu[NR_CPUS];
};
#define INT_ENABLE_OFFSET(v) 		  \
    (sizeof(vcpu_info_t) * (v)->vcpu_id + \
    offsetof(vcpu_info_t, evtchn_upcall_mask))

struct arch_vcpu {
    /* Save the state of vcpu.
       This is the first entry to speed up accesses.  */
    mapped_regs_t *privregs;

    /* TR and TC.  */
    TR_ENTRY itrs[NITRS];
    TR_ENTRY dtrs[NDTRS];
    TR_ENTRY itlb;
    TR_ENTRY dtlb;

    /* Bit is set if there is a tr/tc for the region.  */
    unsigned char itr_regions;
    unsigned char dtr_regions;
    unsigned char tc_regions;

    unsigned long irr[4];	    /* Interrupt request register.  */
    unsigned long insvc[4];		/* Interrupt in service.  */
    unsigned long iva;
    unsigned long dcr;
    unsigned long domain_itm;
    unsigned long domain_itm_last;

    unsigned long event_callback_ip;		// event callback handler
    unsigned long failsafe_callback_ip; 	// Do we need it?

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
    fpswa_ret_t fpswa_ret;	/* save return values of FPSWA emulation */
    struct timer hlt_timer;
    struct arch_vmx_struct arch_vmx; /* Virtual Machine Extensions */

#define INVALID_PROCESSOR       INT_MAX
    int last_processor;
};

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
