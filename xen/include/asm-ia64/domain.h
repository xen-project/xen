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

extern void domain_relinquish_resources(struct domain *);

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

struct arch_domain {
    struct mm_struct mm;
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

    /* OS boot rendez vous.  */
    unsigned long boot_rdv_ip;
    unsigned long boot_rdv_r1;

    /* SAL return point.  */
    unsigned long sal_return_addr;

    u64 xen_vastart;
    u64 xen_vaend;
    u64 shared_info_va;
    unsigned long initrd_start;
    unsigned long initrd_len;
    char *cmdline;
    /* There are these for EFI_SET_VIRTUAL_ADDRESS_MAP emulation. */
    int efi_virt_mode;		/* phys : 0 , virt : 1 */
    /* Metaphysical address to efi_runtime_services_t in domain firmware memory is set. */
    void *efi_runtime;
    /* Metaphysical address to fpswa_interface_t in domain firmware memory is set. */
    void *fpswa_inf;
};
#define xen_vastart arch.xen_vastart
#define xen_vaend arch.xen_vaend
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
    struct arch_vmx_struct arch_vmx; /* Virtual Machine Extensions */
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
