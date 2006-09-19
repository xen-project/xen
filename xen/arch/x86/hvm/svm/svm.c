/*
 * svm.c: handling SVM architecture-related VM exits
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, AMD Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/hypercall.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/shadow.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/io.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>
#include <asm/hvm/svm/vmmcall.h>
#include <asm/hvm/svm/intr.h>
#include <public/sched.h>

#define SVM_EXTRA_DEBUG

#define set_segment_register(name, value)  \
       __asm__ __volatile__ ( "movw %%ax ,%%" STR(name) "" : : "a" (value) )

/* External functions. We should move these to some suitable header file(s) */

extern void do_nmi(struct cpu_user_regs *, unsigned long);
extern int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip,
                                int inst_len);
 extern uint32_t vlapic_update_ppr(struct vlapic *vlapic);
extern asmlinkage void do_IRQ(struct cpu_user_regs *);
extern void send_pio_req(struct cpu_user_regs *regs, unsigned long port,
                         unsigned long count, int size, long value, int dir, int pvalid);
extern int svm_instrlen(struct cpu_user_regs *regs, int mode);
extern void svm_dump_inst(unsigned long eip);
extern int svm_dbg_on;
void svm_dump_regs(const char *from, struct cpu_user_regs *regs);

static void svm_relinquish_guest_resources(struct domain *d);
static int svm_do_vmmcall_reset_to_realmode(struct vcpu *v,
                                            struct cpu_user_regs *regs);

/* va of hardware host save area     */
static void *hsa[NR_CPUS] __read_mostly;

/* vmcb used for extended host state */
static void *root_vmcb[NR_CPUS] __read_mostly;

/* physical address of above for host VMSAVE/VMLOAD */
u64 root_vmcb_pa[NR_CPUS] __read_mostly;


/* ASID API */
enum {
    ASID_AVAILABLE = 0,
    ASID_INUSE,
    ASID_RETIRED
};
#define   INITIAL_ASID      0
#define   ASID_MAX          64
 
struct asid_pool {
    spinlock_t asid_lock;
    u32 asid[ASID_MAX];
};

static DEFINE_PER_CPU(struct asid_pool, asid_pool);


/*
 * Initializes the POOL of ASID used by the guests per core.
 */
void asidpool_init(int core)
{
    int i;

    spin_lock_init(&per_cpu(asid_pool,core).asid_lock);

    /* Host ASID is always in use */
    per_cpu(asid_pool,core).asid[INITIAL_ASID] = ASID_INUSE;
    for ( i = 1; i < ASID_MAX; i++ )
        per_cpu(asid_pool,core).asid[i] = ASID_AVAILABLE;
}


/* internal function to get the next available ASID */
static int asidpool_fetch_next(struct vmcb_struct *vmcb, int core)
{
    int i;  
    for ( i = 1; i < ASID_MAX; i++ )
    {
        if ( per_cpu(asid_pool,core).asid[i] == ASID_AVAILABLE )
        {
            vmcb->guest_asid = i;
            per_cpu(asid_pool,core).asid[i] = ASID_INUSE;
            return i;
        }
    }
    return -1;
}


/*
 * This functions assigns on the passed VMCB, the next
 * available ASID number. If none are available, the
 * TLB flush flag is set, and all retireds ASID
 * are made available. 
 *
 *  Returns: 1 -- sucess;
 *           0 -- failure -- no more ASID numbers 
 *                           available.
 */
int asidpool_assign_next( struct vmcb_struct *vmcb, int retire_current,
                          int oldcore, int newcore )
{
    int i;
    int res = 1;
    static unsigned long cnt=0;

    spin_lock(&per_cpu(asid_pool,oldcore).asid_lock);
    if( retire_current && vmcb->guest_asid ) {
        per_cpu(asid_pool,oldcore).asid[vmcb->guest_asid & (ASID_MAX-1)] = 
            ASID_RETIRED;
    }
    spin_unlock(&per_cpu(asid_pool,oldcore).asid_lock);
    spin_lock(&per_cpu(asid_pool,newcore).asid_lock);
    if( asidpool_fetch_next( vmcb, newcore ) < 0 ) {
        if (svm_dbg_on)
            printk( "SVM: tlb(%ld)\n", cnt++ );
        /* FLUSH the TLB and all retired slots are made available */ 
        vmcb->tlb_control = 1;
        for( i = 1; i < ASID_MAX; i++ ) {
            if( per_cpu(asid_pool,newcore).asid[i] == ASID_RETIRED ) {
                per_cpu(asid_pool,newcore).asid[i] = ASID_AVAILABLE;
            }
        }
        /* Get the First slot available */ 
        res = asidpool_fetch_next( vmcb, newcore ) > 0;
    }
    spin_unlock(&per_cpu(asid_pool,newcore).asid_lock);
    return res;
}

void asidpool_retire( struct vmcb_struct *vmcb, int core )
{
    spin_lock(&per_cpu(asid_pool,core).asid_lock);
    if( vmcb->guest_asid ) {
        per_cpu(asid_pool,core).asid[vmcb->guest_asid & (ASID_MAX-1)] = 
            ASID_RETIRED;
    }
    spin_unlock(&per_cpu(asid_pool,core).asid_lock);
}

static inline void svm_inject_exception(struct vcpu *v, int trap, 
                                        int ev, int error_code)
{
    eventinj_t event;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    event.bytes = 0;            
    event.fields.v = 1;
    event.fields.type = EVENTTYPE_EXCEPTION;
    event.fields.vector = trap;
    event.fields.ev = ev;
    event.fields.errorcode = error_code;

    ASSERT(vmcb->eventinj.fields.v == 0);
    
    vmcb->eventinj = event;
}

static void stop_svm(void)
{
    u32 eax, edx;    
    int cpu = smp_processor_id();

    /* We turn off the EFER_SVME bit. */
    rdmsr(MSR_EFER, eax, edx);
    eax &= ~EFER_SVME;
    wrmsr(MSR_EFER, eax, edx);
 
    /* release the HSA */
    free_host_save_area(hsa[cpu]);
    hsa[cpu] = NULL;
    wrmsr(MSR_K8_VM_HSAVE_PA, 0, 0 );

    /* free up the root vmcb */
    free_vmcb(root_vmcb[cpu]);
    root_vmcb[cpu] = NULL;
    root_vmcb_pa[cpu] = 0;

    printk("AMD SVM Extension is disabled.\n");
}


static void svm_store_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *regs, unsigned long *crs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( regs != NULL )
    {
        regs->eip    = vmcb->rip;
        regs->esp    = vmcb->rsp;
        regs->eflags = vmcb->rflags;
        regs->cs     = vmcb->cs.sel;
        regs->ds     = vmcb->ds.sel;
        regs->es     = vmcb->es.sel;
        regs->ss     = vmcb->ss.sel;
        regs->gs     = vmcb->gs.sel;
        regs->fs     = vmcb->fs.sel;
    }

    if ( crs != NULL )
    {
        /* Returning the guest's regs */
        crs[0] = v->arch.hvm_svm.cpu_shadow_cr0;
        crs[2] = v->arch.hvm_svm.cpu_cr2;
        crs[3] = v->arch.hvm_svm.cpu_cr3;
        crs[4] = v->arch.hvm_svm.cpu_shadow_cr4;
    }
}

static int svm_paging_enabled(struct vcpu *v)
{
    unsigned long cr0;

    cr0 = v->arch.hvm_svm.cpu_shadow_cr0;

    return (cr0 & X86_CR0_PE) && (cr0 & X86_CR0_PG);
}


#define IS_CANO_ADDRESS(add) 1

static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *vc = current;
    struct vmcb_struct *vmcb = vc->arch.hvm_svm.vmcb;

    switch (regs->ecx)
    {
    case MSR_EFER:
        msr_content = vmcb->efer;      
        msr_content &= ~EFER_SVME;
        break;

    case MSR_FS_BASE:
        msr_content = vmcb->fs.base;
        break;

    case MSR_GS_BASE:
        msr_content = vmcb->gs.base;
        break;

    case MSR_SHADOW_GS_BASE:
        msr_content = vmcb->kerngsbase;
        break;

    case MSR_STAR:
        msr_content = vmcb->star;
        break;
 
    case MSR_LSTAR:
        msr_content = vmcb->lstar;
        break;
 
    case MSR_CSTAR:
        msr_content = vmcb->cstar;
        break;
 
    case MSR_SYSCALL_MASK:
        msr_content = vmcb->sfmask;
        break;
    default:
        return 0;
    }

    HVM_DBG_LOG(DBG_LEVEL_2, "mode_do_msr_read: msr_content: %"PRIx64"\n", 
                msr_content);

    regs->eax = msr_content & 0xffffffff;
    regs->edx = msr_content >> 32;
    return 1;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content = regs->eax | ((u64)regs->edx << 32);
    struct vcpu *vc = current;
    struct vmcb_struct *vmcb = vc->arch.hvm_svm.vmcb;

    HVM_DBG_LOG(DBG_LEVEL_1, "mode_do_msr_write msr %lx "
                "msr_content %"PRIx64"\n", 
                (unsigned long)regs->ecx, msr_content);

    switch (regs->ecx)
    {
    case MSR_EFER:
#ifdef __x86_64__
        /* offending reserved bit will cause #GP */
        if ( msr_content & ~(EFER_LME | EFER_LMA | EFER_NX | EFER_SCE) )
        {
            printk("trying to set reserved bit in EFER\n");
            svm_inject_exception(vc, TRAP_gp_fault, 1, 0);
            return 0;
        }

        /* LME: 0 -> 1 */
        if ( msr_content & EFER_LME &&
             !test_bit(SVM_CPU_STATE_LME_ENABLED, &vc->arch.hvm_svm.cpu_state))
        {
            if ( svm_paging_enabled(vc) ||
                 !test_bit(SVM_CPU_STATE_PAE_ENABLED,
                           &vc->arch.hvm_svm.cpu_state) )
            {
                printk("trying to set LME bit when "
                       "in paging mode or PAE bit is not set\n");
                svm_inject_exception(vc, TRAP_gp_fault, 1, 0);
                return 0;
            }
            set_bit(SVM_CPU_STATE_LME_ENABLED, &vc->arch.hvm_svm.cpu_state);
        }

        /* We have already recorded that we want LME, so it will be set 
         * next time CR0 gets updated. So we clear that bit and continue.
         */
        if ((msr_content ^ vmcb->efer) & EFER_LME)
            msr_content &= ~EFER_LME;  
        /* No update for LME/LMA since it have no effect */
#endif
        vmcb->efer = msr_content | EFER_SVME;
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
        if (!(SVM_LONG_GUEST(vc)))
            domain_crash_synchronous();

        if (!IS_CANO_ADDRESS(msr_content))
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Not cano address of msr write\n");
            svm_inject_exception(vc, TRAP_gp_fault, 1, 0);
        }

        if (regs->ecx == MSR_FS_BASE)
            vmcb->fs.base = msr_content;
        else 
            vmcb->gs.base = msr_content;
        break;

    case MSR_SHADOW_GS_BASE:
        vmcb->kerngsbase = msr_content;
        break;
 
    case MSR_STAR:
        vmcb->star = msr_content;
        break;
 
    case MSR_LSTAR:
        vmcb->lstar = msr_content;
        break;
 
    case MSR_CSTAR:
        vmcb->cstar = msr_content;
        break;
 
    case MSR_SYSCALL_MASK:
        vmcb->sfmask = msr_content;
        break;

    default:
        return 0;
    }
    return 1;
}


#define loaddebug(_v,_reg) \
    __asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_v)->debugreg[_reg]))
#define savedebug(_v,_reg) \
    __asm__ __volatile__ ("mov %%db" #_reg ",%0" : : "r" ((_v)->debugreg[_reg]))


static inline void svm_save_dr(struct vcpu *v)
{
    if (v->arch.hvm_vcpu.flag_dr_dirty)
    {
        /* clear the DR dirty flag and re-enable intercepts for DR accesses */ 
        v->arch.hvm_vcpu.flag_dr_dirty = 0;
        v->arch.hvm_svm.vmcb->dr_intercepts = DR_INTERCEPT_ALL_WRITES;

        savedebug(&v->arch.guest_context, 0);    
        savedebug(&v->arch.guest_context, 1);    
        savedebug(&v->arch.guest_context, 2);    
        savedebug(&v->arch.guest_context, 3);    
    }
}


static inline void __restore_debug_registers(struct vcpu *v)
{
    loaddebug(&v->arch.guest_context, 0);
    loaddebug(&v->arch.guest_context, 1);
    loaddebug(&v->arch.guest_context, 2);
    loaddebug(&v->arch.guest_context, 3);
}


static inline void svm_restore_dr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if (!vmcb)
        return;

    if (unlikely(vmcb->dr7 & 0xFF))
        __restore_debug_registers(v);
}


static int svm_realmode(struct vcpu *v)
{
    unsigned long cr0 = v->arch.hvm_svm.cpu_shadow_cr0;
    unsigned long eflags = v->arch.hvm_svm.vmcb->rflags;

    return (eflags & X86_EFLAGS_VM) || !(cr0 & X86_CR0_PE);
}

int svm_guest_x86_mode(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long cr0 = vmcb->cr0, eflags = vmcb->rflags, mode;
    /* check which operating mode the guest is running */
    if( vmcb->efer & EFER_LMA )
        mode = vmcb->cs.attributes.fields.l ? 8 : 4;
    else
        mode = (eflags & X86_EFLAGS_VM) || !(cr0 & X86_CR0_PE) ? 2 : 4;
    return mode;
}

int svm_instruction_length(struct vcpu *v)
{
    return svm_instrlen(guest_cpu_user_regs(), svm_guest_x86_mode(v));
}

void svm_update_host_cr3(struct vcpu *v)
{
    /* SVM doesn't have a HOST_CR3 equivalent to update. */
}

unsigned long svm_get_ctrl_reg(struct vcpu *v, unsigned int num)
{
    switch ( num )
    {
    case 0:
        return v->arch.hvm_svm.cpu_shadow_cr0;
    case 2:
        return v->arch.hvm_svm.cpu_cr2;
    case 3:
        return v->arch.hvm_svm.cpu_cr3;
    case 4:
        return v->arch.hvm_svm.cpu_shadow_cr4;
    default:
        BUG();
    }
    return 0;                   /* dummy */
}


/* Make sure that xen intercepts any FP accesses from current */
static void svm_stts(struct vcpu *v) 
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    /*
     * If the guest does not have TS enabled then we must cause and handle an 
     * exception on first use of the FPU. If the guest *does* have TS enabled 
     * then this is not necessary: no FPU activity can occur until the guest 
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    if ( !(v->arch.hvm_svm.cpu_shadow_cr0 & X86_CR0_TS) )
    {
        v->arch.hvm_svm.vmcb->exception_intercepts |= EXCEPTION_BITMAP_NM;
        vmcb->cr0 |= X86_CR0_TS;
    }
}


static void svm_set_tsc_offset(struct vcpu *v, u64 offset)
{
    v->arch.hvm_svm.vmcb->tsc_offset = offset;
}


/* SVM-specific intitialization code for VCPU application processors */
static void svm_init_ap_context(struct vcpu_guest_context *ctxt, 
                                int vcpuid, int trampoline_vector)
{
    int i;
    struct vcpu *v, *bsp = current;
    struct domain *d = bsp->domain;
    cpu_user_regs_t *regs;;

  
    if ((v = d->vcpu[vcpuid]) == NULL)
    {
        printk("vcpuid %d is invalid!  good-bye.\n", vcpuid);
        domain_crash_synchronous();
    }
    regs = &v->arch.guest_context.user_regs;

    memset(ctxt, 0, sizeof(*ctxt));
    for (i = 0; i < 256; ++i)
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs = FLAT_KERNEL_CS;
    }


    /*
     * We execute the trampoline code in real mode. The trampoline vector
     * passed to us is page alligned and is the physicall frame number for
     * the code. We will execute this code in real mode. 
     */
    ctxt->user_regs.eip = 0x0;
    ctxt->user_regs.cs = (trampoline_vector << 8);
    ctxt->flags = VGCF_HVM_GUEST;
}

static void svm_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    memset(hypercall_page, 0, PAGE_SIZE);

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(u32 *)(p + 1) = i;
        *(u8  *)(p + 5) = 0x0f; /* vmmcall */
        *(u8  *)(p + 6) = 0x01;
        *(u8  *)(p + 7) = 0xd9;
        *(u8  *)(p + 8) = 0xc3; /* ret */
    }

    /* Don't support HYPERVISOR_iret at the moment */
    *(u16 *)(hypercall_page + (__HYPERVISOR_iret * 32)) = 0x0b0f; /* ud2 */
}


int svm_dbg_on = 0;

static inline int svm_do_debugout(unsigned long exit_code)
{
    int i;

    static unsigned long counter = 0;
    static unsigned long works[] =
    {
        VMEXIT_IOIO,
        VMEXIT_HLT,
        VMEXIT_CPUID,
        VMEXIT_DR0_READ,
        VMEXIT_DR1_READ,
        VMEXIT_DR2_READ,
        VMEXIT_DR3_READ,
        VMEXIT_DR6_READ,
        VMEXIT_DR7_READ,
        VMEXIT_DR0_WRITE,
        VMEXIT_DR1_WRITE,
        VMEXIT_DR2_WRITE,
        VMEXIT_DR3_WRITE,
        VMEXIT_CR0_READ,
        VMEXIT_CR0_WRITE,
        VMEXIT_CR3_READ,
        VMEXIT_CR4_READ, 
        VMEXIT_MSR,
        VMEXIT_CR0_WRITE,
        VMEXIT_CR3_WRITE,
        VMEXIT_CR4_WRITE,
        VMEXIT_EXCEPTION_PF,
        VMEXIT_INTR,
        VMEXIT_INVLPG,
        VMEXIT_EXCEPTION_NM
    };


#if 0
    if (svm_dbg_on && exit_code != 0x7B)
        return 1;
#endif

    counter++;

#if 0
    if ((exit_code == 0x4E 
         || exit_code == VMEXIT_CR0_READ 
         || exit_code == VMEXIT_CR0_WRITE) 
        && counter < 200000)
        return 0;

    if ((exit_code == 0x4E) && counter < 500000)
        return 0;
#endif

    for (i = 0; i < sizeof(works) / sizeof(works[0]); i++)
        if (exit_code == works[i])
            return 0;

    return 1;
}

static void save_svm_cpu_user_regs(struct vcpu *v, struct cpu_user_regs *ctxt)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);

    ctxt->eax = vmcb->rax;
    ctxt->ss = vmcb->ss.sel;
    ctxt->esp = vmcb->rsp;
    ctxt->eflags = vmcb->rflags;
    ctxt->cs = vmcb->cs.sel;
    ctxt->eip = vmcb->rip;
    
    ctxt->gs = vmcb->gs.sel;
    ctxt->fs = vmcb->fs.sel;
    ctxt->es = vmcb->es.sel;
    ctxt->ds = vmcb->ds.sel;
}

static void svm_store_cpu_user_regs(struct cpu_user_regs *regs, struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    regs->eip    = vmcb->rip;
    regs->esp    = vmcb->rsp;
    regs->eflags = vmcb->rflags;
    regs->cs     = vmcb->cs.sel;
    regs->ds     = vmcb->ds.sel;
    regs->es     = vmcb->es.sel;
    regs->ss     = vmcb->ss.sel;
}

/* XXX Use svm_load_cpu_guest_regs instead */
static void svm_load_cpu_user_regs(struct vcpu *v, struct cpu_user_regs *regs)
{ 
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 *intercepts = &v->arch.hvm_svm.vmcb->exception_intercepts;
    
    /* Write the guest register value into VMCB */
    vmcb->rax      = regs->eax;
    vmcb->ss.sel   = regs->ss;
    vmcb->rsp      = regs->esp;   
    vmcb->rflags   = regs->eflags;
    vmcb->cs.sel   = regs->cs;
    vmcb->rip      = regs->eip;
    if (regs->eflags & EF_TF)
        *intercepts |= EXCEPTION_BITMAP_DB;
    else
        *intercepts &= ~EXCEPTION_BITMAP_DB;
}

static void svm_load_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *regs)
{
    svm_load_cpu_user_regs(v, regs);
}

int svm_long_mode_enabled(struct vcpu *v)
{
    return SVM_LONG_GUEST(v);
}



static void arch_svm_do_launch(struct vcpu *v) 
{
    cpu_user_regs_t *regs = &current->arch.guest_context.user_regs;
    int error;

#if 0
    if (svm_dbg_on)
        printk("Do launch\n");
#endif
    error = construct_vmcb(&v->arch.hvm_svm, regs);
    if ( error < 0 )
    {
        if (v->vcpu_id == 0) {
            printk("Failed to construct a new VMCB for BSP.\n");
        } else {
            printk("Failed to construct a new VMCB for AP %d\n", v->vcpu_id);
        }
        domain_crash_synchronous();
    }

    svm_do_launch(v);
#if 0
    if (svm_dbg_on)
        svm_dump_host_regs(__func__);
#endif
    if (v->vcpu_id != 0) 
    {
        u16 cs_sel = regs->cs;
        /*
         * This is the launch of an AP; set state so that we begin executing
         * the trampoline code in real-mode.
         */
        svm_do_vmmcall_reset_to_realmode(v, regs);  
        /* Adjust the state to execute the trampoline code.*/
        v->arch.hvm_svm.vmcb->rip = 0;
        v->arch.hvm_svm.vmcb->cs.sel= cs_sel;
        v->arch.hvm_svm.vmcb->cs.base = (cs_sel << 4);
    }
      
    reset_stack_and_jump(svm_asm_do_launch);
}

static void svm_freeze_time(struct vcpu *v)
{
    struct periodic_time *pt=&v->domain->arch.hvm_domain.pl_time.periodic_tm;
    
    if ( pt->enabled && pt->first_injected && !v->arch.hvm_vcpu.guest_time ) {
        v->arch.hvm_vcpu.guest_time = hvm_get_guest_time(v);
        stop_timer(&(pt->timer));
    }
}


static void svm_ctxt_switch_from(struct vcpu *v)
{
    svm_freeze_time(v);
    svm_save_dr(v);
}

static void svm_ctxt_switch_to(struct vcpu *v)
{
#ifdef  __x86_64__
    /* 
     * This is required, because VMRUN does consistency check
     * and some of the DOM0 selectors are pointing to 
     * invalid GDT locations, and cause AMD processors
     * to shutdown.
     */
    set_segment_register(ds, 0);
    set_segment_register(es, 0);
    set_segment_register(ss, 0);
#endif
    svm_restore_dr(v);
}


static void svm_final_setup_guest(struct vcpu *v)
{
    struct domain *d = v->domain;

    v->arch.schedule_tail    = arch_svm_do_launch;
    v->arch.ctxt_switch_from = svm_ctxt_switch_from;
    v->arch.ctxt_switch_to   = svm_ctxt_switch_to;

    if ( v != d->vcpu[0] )
        return;

    if ( !shadow_mode_external(d) )
    {
        DPRINTK("Can't init HVM for dom %u vcpu %u: "
                "not in shadow external mode\n", d->domain_id, v->vcpu_id);
        domain_crash(d);
    }

    /* 
     * Required to do this once per domain
     * TODO: add a seperate function to do these.
     */
    memset(&d->shared_info->evtchn_mask[0], 0xff, 
           sizeof(d->shared_info->evtchn_mask));       
}


static int svm_initialize_guest_resources(struct vcpu *v)
{
    svm_final_setup_guest(v);
    return 1;
}


int start_svm(void)
{
    u32 eax, ecx, edx;
    u32 phys_hsa_lo, phys_hsa_hi;   
    u64 phys_hsa;
    int cpu = smp_processor_id();
 
    /* Xen does not fill x86_capability words except 0. */
    ecx = cpuid_ecx(0x80000001);
    boot_cpu_data.x86_capability[5] = ecx;
    
    if (!(test_bit(X86_FEATURE_SVME, &boot_cpu_data.x86_capability)))
        return 0;
    
    if (!(hsa[cpu] = alloc_host_save_area()))
        return 0;
    
    rdmsr(MSR_EFER, eax, edx);
    eax |= EFER_SVME;
    wrmsr(MSR_EFER, eax, edx);
    asidpool_init( cpu );    
    printk("AMD SVM Extension is enabled for cpu %d.\n", cpu );

    /* Initialize the HSA for this core */
    phys_hsa = (u64) virt_to_maddr(hsa[cpu]);
    phys_hsa_lo = (u32) phys_hsa;
    phys_hsa_hi = (u32) (phys_hsa >> 32);    
    wrmsr(MSR_K8_VM_HSAVE_PA, phys_hsa_lo, phys_hsa_hi);
  
    if (!(root_vmcb[cpu] = alloc_vmcb())) 
        return 0;
    root_vmcb_pa[cpu] = virt_to_maddr(root_vmcb[cpu]);

    if (cpu == 0)
        setup_vmcb_dump();

    /* Setup HVM interfaces */
    hvm_funcs.disable = stop_svm;

    hvm_funcs.initialize_guest_resources = svm_initialize_guest_resources;
    hvm_funcs.relinquish_guest_resources = svm_relinquish_guest_resources;

    hvm_funcs.store_cpu_guest_regs = svm_store_cpu_guest_regs;
    hvm_funcs.load_cpu_guest_regs = svm_load_cpu_guest_regs;

    hvm_funcs.realmode = svm_realmode;
    hvm_funcs.paging_enabled = svm_paging_enabled;
    hvm_funcs.long_mode_enabled = svm_long_mode_enabled;
    hvm_funcs.guest_x86_mode = svm_guest_x86_mode;
    hvm_funcs.instruction_length = svm_instruction_length;
    hvm_funcs.get_guest_ctrl_reg = svm_get_ctrl_reg;

    hvm_funcs.update_host_cr3 = svm_update_host_cr3;
    
    hvm_funcs.stts = svm_stts;
    hvm_funcs.set_tsc_offset = svm_set_tsc_offset;

    hvm_funcs.init_ap_context = svm_init_ap_context;
    hvm_funcs.init_hypercall_page = svm_init_hypercall_page;

    hvm_enabled = 1;

    return 1;
}


static void svm_relinquish_guest_resources(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            continue;

        destroy_vmcb(&v->arch.hvm_svm);
        kill_timer(&v->arch.hvm_vcpu.hlt_timer);
        if ( hvm_apic_support(v->domain) && (VLAPIC(v) != NULL) ) 
        {
            kill_timer( &(VLAPIC(v)->vlapic_timer) );
            unmap_domain_page_global(VLAPIC(v)->regs);
            free_domheap_page(VLAPIC(v)->regs_page);
            xfree(VLAPIC(v));
        }
        hvm_release_assist_channel(v);
    }

    kill_timer(&d->arch.hvm_domain.pl_time.periodic_tm.timer);

    if ( d->arch.hvm_domain.shared_page_va )
        unmap_domain_page_global(
            (void *)d->arch.hvm_domain.shared_page_va);

    if ( d->arch.hvm_domain.buffered_io_va )
        unmap_domain_page_global((void *)d->arch.hvm_domain.buffered_io_va);
}


static void svm_migrate_timers(struct vcpu *v)
{
    struct periodic_time *pt = 
        &(v->domain->arch.hvm_domain.pl_time.periodic_tm);

    if ( pt->enabled ) {
        migrate_timer( &pt->timer, v->processor );
        migrate_timer( &v->arch.hvm_vcpu.hlt_timer, v->processor );
    }
    if ( hvm_apic_support(v->domain) && VLAPIC( v ))
        migrate_timer( &(VLAPIC(v)->vlapic_timer ), v->processor );
}


void arch_svm_do_resume(struct vcpu *v) 
{
    /* pinning VCPU to a different core? */
    if ( v->arch.hvm_svm.launch_core == smp_processor_id()) {
        hvm_do_resume( v );
        reset_stack_and_jump( svm_asm_do_resume );
    }
    else {
        if (svm_dbg_on)
            printk("VCPU core pinned: %d to %d\n", 
                   v->arch.hvm_svm.launch_core, smp_processor_id() );
        v->arch.hvm_svm.launch_core = smp_processor_id();
        svm_migrate_timers( v );
        hvm_do_resume( v );
        reset_stack_and_jump( svm_asm_do_resume );
    }
}



static int svm_do_page_fault(unsigned long va, struct cpu_user_regs *regs) 
{
    struct vcpu *v = current;
    unsigned long eip;
    int result;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);

//#if HVM_DEBUG
    eip = vmcb->rip;
    HVM_DBG_LOG(DBG_LEVEL_VMMU, 
                "svm_do_page_fault = 0x%lx, eip = %lx, error_code = %lx",
                va, eip, (unsigned long)regs->error_code);
//#endif

    result = shadow_fault(va, regs); 

    if( result ) {
        /* Let's make sure that the Guest TLB is flushed */
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    }

    return result;
}


static void svm_do_no_device_fault(struct vmcb_struct *vmcb)
{
    struct vcpu *v = current;

    setup_fpu(v);    
    vmcb->exception_intercepts &= ~EXCEPTION_BITMAP_NM;

    if ( !(v->arch.hvm_svm.cpu_shadow_cr0 & X86_CR0_TS) )
        vmcb->cr0 &= ~X86_CR0_TS;
}


static void svm_do_general_protection_fault(struct vcpu *v, 
                                            struct cpu_user_regs *regs) 
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long eip, error_code;

    ASSERT(vmcb);

    eip = vmcb->rip;
    error_code = vmcb->exitinfo1;

    if (vmcb->idtr.limit == 0) {
        printf("Huh? We got a GP Fault with an invalid IDTR!\n");
        svm_dump_vmcb(__func__, vmcb);
        svm_dump_regs(__func__, regs);
        svm_dump_inst(vmcb->rip);
        __hvm_bug(regs);
    }

    HVM_DBG_LOG(DBG_LEVEL_1,
                "svm_general_protection_fault: eip = %lx, erro_code = %lx",
                eip, error_code);

    HVM_DBG_LOG(DBG_LEVEL_1, 
                "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                (unsigned long)regs->eax, (unsigned long)regs->ebx,
                (unsigned long)regs->ecx, (unsigned long)regs->edx,
                (unsigned long)regs->esi, (unsigned long)regs->edi);
      
    /* Reflect it back into the guest */
    svm_inject_exception(v, TRAP_gp_fault, 1, error_code);
}

/* Reserved bits ECX: [31:14], [12:4], [2:1]*/
#define SVM_VCPU_CPUID_L1_ECX_RESERVED 0xffffdff6
/* Reserved bits EDX: [31:29], [27], [22:20], [18], [10] */
#define SVM_VCPU_CPUID_L1_EDX_RESERVED 0xe8740400

static void svm_vmexit_do_cpuid(struct vmcb_struct *vmcb, unsigned long input, 
                                struct cpu_user_regs *regs) 
{
    unsigned int eax, ebx, ecx, edx;
    unsigned long eip;
    struct vcpu *v = current;
    int inst_len;

    ASSERT(vmcb);

    eip = vmcb->rip;

    HVM_DBG_LOG(DBG_LEVEL_1, 
                "do_cpuid: (eax) %lx, (ebx) %lx, (ecx) %lx, (edx) %lx,"
                " (esi) %lx, (edi) %lx",
                (unsigned long)regs->eax, (unsigned long)regs->ebx,
                (unsigned long)regs->ecx, (unsigned long)regs->edx,
                (unsigned long)regs->esi, (unsigned long)regs->edi);

    if ( !cpuid_hypervisor_leaves(input, &eax, &ebx, &ecx, &edx) )
    {
        cpuid(input, &eax, &ebx, &ecx, &edx);       
        if (input == 0x00000001 || input == 0x80000001 )
        {
            if ( !hvm_apic_support(v->domain) ||
                 !vlapic_global_enabled((VLAPIC(v))) )
            {
                /* Since the apic is disabled, avoid any confusion 
                   about SMP cpus being available */
                clear_bit(X86_FEATURE_APIC, &edx);
            }
#if CONFIG_PAGING_LEVELS >= 3
            if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_PAE_ENABLED] )
#endif
            {
                clear_bit(X86_FEATURE_PAE, &edx);
                if (input == 0x80000001 )
                   clear_bit(X86_FEATURE_NX & 31, &edx);
            }
            clear_bit(X86_FEATURE_PSE36, &edx);
            /* Disable machine check architecture */
            clear_bit(X86_FEATURE_MCA, &edx);
            clear_bit(X86_FEATURE_MCE, &edx);
            if (input == 0x00000001 )
            {
                /* Clear out reserved bits. */
                ecx &= ~SVM_VCPU_CPUID_L1_ECX_RESERVED;
                edx &= ~SVM_VCPU_CPUID_L1_EDX_RESERVED;

                clear_bit(X86_FEATURE_MWAIT & 31, &ecx);

                /* Guest should only see one logical processor.
                 * See details on page 23 of AMD CPUID Specification. 
                 */
                clear_bit(X86_FEATURE_HT, &edx);  /* clear the hyperthread bit */
                ebx &= 0xFF00FFFF;  /* clear the logical processor count when HTT=0 */
                ebx |= 0x00010000;  /* set to 1 just for precaution */
            }
            else
            {
                /* Clear the Cmp_Legacy bit 
                 * This bit is supposed to be zero when HTT = 0.
                 * See details on page 23 of AMD CPUID Specification. 
                 */
                clear_bit(X86_FEATURE_CMP_LEGACY & 31, &ecx);
                /* Make SVM feature invisible to the guest. */
                clear_bit(X86_FEATURE_SVME & 31, &ecx);
#ifdef __i386__
                /* Mask feature for Intel ia32e or AMD long mode. */
                clear_bit(X86_FEATURE_LAHF_LM & 31, &ecx);

                clear_bit(X86_FEATURE_LM & 31, &edx);
                clear_bit(X86_FEATURE_SYSCALL & 31, &edx);
#endif
                /* So far, we do not support 3DNow for the guest. */
                clear_bit(X86_FEATURE_3DNOW & 31, &edx);
                clear_bit(X86_FEATURE_3DNOWEXT & 31, &edx);
            }
        }
        else if ( ( input == 0x80000007 ) || ( input == 0x8000000A  ) )
        {
            /* Mask out features of power management and SVM extension. */
            eax = ebx = ecx = edx = 0;
        }
        else if ( input == 0x80000008 )
        {
            /* Make sure Number of CPU core is 1 when HTT=0 */
            ecx &= 0xFFFFFF00; 
        }
    }

    regs->eax = (unsigned long)eax;
    regs->ebx = (unsigned long)ebx;
    regs->ecx = (unsigned long)ecx;
    regs->edx = (unsigned long)edx;

    HVM_DBG_LOG(DBG_LEVEL_1, 
                "svm_vmexit_do_cpuid: eip: %lx, input: %lx, out:eax=%x, "
                "ebx=%x, ecx=%x, edx=%x",
                eip, input, eax, ebx, ecx, edx);

    inst_len = __get_instruction_length(vmcb, INSTR_CPUID, NULL);
    ASSERT(inst_len > 0);
    __update_guest_eip(vmcb, inst_len);
}


static inline unsigned long *get_reg_p(unsigned int gpreg, 
                                       struct cpu_user_regs *regs, struct vmcb_struct *vmcb)
{
    unsigned long *reg_p = NULL;
    switch (gpreg)
    {
    case SVM_REG_EAX:
        reg_p = (unsigned long *)&regs->eax;
        break;
    case SVM_REG_EBX:
        reg_p = (unsigned long *)&regs->ebx;
        break;
    case SVM_REG_ECX:
        reg_p = (unsigned long *)&regs->ecx;
        break;
    case SVM_REG_EDX:
        reg_p = (unsigned long *)&regs->edx;
        break;
    case SVM_REG_EDI:
        reg_p = (unsigned long *)&regs->edi;
        break;
    case SVM_REG_ESI:
        reg_p = (unsigned long *)&regs->esi;
        break;
    case SVM_REG_EBP:
        reg_p = (unsigned long *)&regs->ebp;
        break;
    case SVM_REG_ESP:
        reg_p = (unsigned long *)&vmcb->rsp;
        break;
#ifdef __x86_64__
    case SVM_REG_R8:
        reg_p = (unsigned long *)&regs->r8;
        break;
    case SVM_REG_R9:
        reg_p = (unsigned long *)&regs->r9;
        break;
    case SVM_REG_R10:
        reg_p = (unsigned long *)&regs->r10;
        break;
    case SVM_REG_R11:
        reg_p = (unsigned long *)&regs->r11;
        break;
    case SVM_REG_R12:
        reg_p = (unsigned long *)&regs->r12;
        break;
    case SVM_REG_R13:
        reg_p = (unsigned long *)&regs->r13;
        break;
    case SVM_REG_R14:
        reg_p = (unsigned long *)&regs->r14;
        break;
    case SVM_REG_R15:
        reg_p = (unsigned long *)&regs->r15;
        break;
#endif
    default:
        BUG();
    } 
    
    return reg_p;
}


static inline unsigned long get_reg(unsigned int gpreg, 
                                    struct cpu_user_regs *regs, struct vmcb_struct *vmcb)
{
    unsigned long *gp;
    gp = get_reg_p(gpreg, regs, vmcb);
    return *gp;
}


static inline void set_reg(unsigned int gpreg, unsigned long value, 
                           struct cpu_user_regs *regs, struct vmcb_struct *vmcb)
{
    unsigned long *gp;
    gp = get_reg_p(gpreg, regs, vmcb);
    *gp = value;
}
                           

static void svm_dr_access(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    v->arch.hvm_vcpu.flag_dr_dirty = 1;

    __restore_debug_registers(v);

    /* allow the guest full access to the debug registers */
    vmcb->dr_intercepts = 0;
}


static void svm_get_prefix_info(
    struct vmcb_struct *vmcb, 
    unsigned int dir, segment_selector_t **seg, unsigned int *asize)
{
    unsigned char inst[MAX_INST_LEN];
    int i;

    memset(inst, 0, MAX_INST_LEN);
    if (inst_copy_from_guest(inst, svm_rip2pointer(vmcb), sizeof(inst)) 
        != MAX_INST_LEN) 
    {
        printk("%s: get guest instruction failed\n", __func__);
        domain_crash_synchronous();
    }

    for (i = 0; i < MAX_INST_LEN; i++)
    {
        switch (inst[i])
        {
        case 0xf3: /* REPZ */
        case 0xf2: /* REPNZ */
        case 0xf0: /* LOCK */
        case 0x66: /* data32 */
#ifdef __x86_64__
            /* REX prefixes */
        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:

        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
#endif
            continue;
        case 0x67: /* addr32 */
            *asize ^= 48;        /* Switch 16/32 bits */
            continue;
        case 0x2e: /* CS */
            *seg = &vmcb->cs;
            continue;
        case 0x36: /* SS */
            *seg = &vmcb->ss;
            continue;
        case 0x26: /* ES */
            *seg = &vmcb->es;
            continue;
        case 0x64: /* FS */
            *seg = &vmcb->fs;
            continue;
        case 0x65: /* GS */
            *seg = &vmcb->gs;
            continue;
        case 0x3e: /* DS */
            *seg = &vmcb->ds;
            continue;
        default:
            break;
        }
        return;
    }
}


/* Get the address of INS/OUTS instruction */
static inline int svm_get_io_address(
    struct vcpu *v, 
    struct cpu_user_regs *regs, unsigned int dir, 
    unsigned long *count, unsigned long *addr)
{
    unsigned long        reg;
    unsigned int         asize = 0;
    unsigned int         isize;
    int                  long_mode;
    ioio_info_t          info;
    segment_selector_t  *seg = NULL;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    info.bytes = vmcb->exitinfo1;

    /* If we're in long mode, we shouldn't check the segment presence & limit */
    long_mode = vmcb->cs.attributes.fields.l && vmcb->efer & EFER_LMA;

    /* d field of cs.attributes is 1 for 32-bit, 0 for 16 or 64 bit. 
     * l field combined with EFER_LMA -> longmode says whether it's 16 or 64 bit. 
     */
    asize = (long_mode)?64:((vmcb->cs.attributes.fields.db)?32:16);


    /* The ins/outs instructions are single byte, so if we have got more 
     * than one byte (+ maybe rep-prefix), we have some prefix so we need 
     * to figure out what it is...
     */
    isize = vmcb->exitinfo2 - vmcb->rip;

    if (info.fields.rep)
        isize --;

    if (isize > 1) 
    {
        svm_get_prefix_info(vmcb, dir, &seg, &asize);
    }

    ASSERT(dir == IOREQ_READ || dir == IOREQ_WRITE);

    if (dir == IOREQ_WRITE)
    {
        reg = regs->esi;
        if (!seg)               /* If no prefix, used DS. */
            seg = &vmcb->ds;
    }
    else
    {
        reg = regs->edi;
        seg = &vmcb->es;        /* Note: This is ALWAYS ES. */
    }

    /* If the segment isn't present, give GP fault! */
    if (!long_mode && !seg->attributes.fields.p) 
    {
        svm_inject_exception(v, TRAP_gp_fault, 1, seg->sel);
        return 0;
    }

    if (asize == 16) 
    {
        *addr = (reg & 0xFFFF);
        *count = regs->ecx & 0xffff;
    }
    else
    {
        *addr = reg;
        *count = regs->ecx;
    }

    if (!long_mode) {
        if (*addr > seg->limit) 
        {
            svm_inject_exception(v, TRAP_gp_fault, 1, seg->sel);
            return 0;
        } 
        else 
        {
            *addr += seg->base;
        }
    }
    

    return 1;
}


static void svm_io_instruction(struct vcpu *v)
{
    struct cpu_user_regs *regs;
    struct hvm_io_op *pio_opp;
    unsigned int port;
    unsigned int size, dir;
    ioio_info_t info;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);
    pio_opp = &current->arch.hvm_vcpu.io_op;
    pio_opp->instr = INSTR_PIO;
    pio_opp->flags = 0;

    regs = &pio_opp->io_context;

    /* Copy current guest state into io instruction state structure. */
    memcpy(regs, guest_cpu_user_regs(), HVM_CONTEXT_STACK_BYTES);
    hvm_store_cpu_guest_regs(v, regs, NULL);

    info.bytes = vmcb->exitinfo1;

    port = info.fields.port; /* port used to be addr */
    dir = info.fields.type; /* direction */ 
    if (info.fields.sz32) 
        size = 4;
    else if (info.fields.sz16)
        size = 2;
    else 
        size = 1;

    HVM_DBG_LOG(DBG_LEVEL_IO, 
                "svm_io_instruction: port 0x%x eip=%x:%"PRIx64", "
                "exit_qualification = %"PRIx64,
                port, vmcb->cs.sel, vmcb->rip, info.bytes);

    /* string instruction */
    if (info.fields.str)
    { 
        unsigned long addr, count;
        int sign = regs->eflags & EF_DF ? -1 : 1;

        if (!svm_get_io_address(v, regs, dir, &count, &addr)) 
        {
            /* We failed to get a valid address, so don't do the IO operation -
             * it would just get worse if we do! Hopefully the guest is handing
             * gp-faults... 
             */
            return;
        }

        /* "rep" prefix */
        if (info.fields.rep) 
        {
            pio_opp->flags |= REPZ;
        }
        else 
        {
            count = 1;
        }

        /*
         * Handle string pio instructions that cross pages or that
         * are unaligned. See the comments in hvm_platform.c/handle_mmio()
         */
        if ((addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK))
        {
            unsigned long value = 0;

            pio_opp->flags |= OVERLAP;

            if (dir == IOREQ_WRITE)
                hvm_copy(&value, addr, size, HVM_COPY_IN);

            send_pio_req(regs, port, 1, size, value, dir, 0);
        } 
        else 
        {
            if ((addr & PAGE_MASK) != ((addr + count * size - 1) & PAGE_MASK))
            {
                if (sign > 0)
                    count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
                else
                    count = (addr & ~PAGE_MASK) / size;
            }
            else    
                regs->eip = vmcb->exitinfo2;

            send_pio_req(regs, port, count, size, addr, dir, 1);
        }
    } 
    else 
    {
        /* 
         * On SVM, the RIP of the intruction following the IN/OUT is saved in
         * ExitInfo2
         */
        regs->eip = vmcb->exitinfo2;

        if (port == 0xe9 && dir == IOREQ_WRITE && size == 1) 
            hvm_print_line(v, regs->eax); /* guest debug output */
    
        send_pio_req(regs, port, 1, size, regs->eax, dir, 0);
    }
}

static int svm_set_cr0(unsigned long value)
{
    struct vcpu *v = current;
    unsigned long mfn;
    int paging_enabled;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long old_base_mfn;
  
    ASSERT(vmcb);

    /* We don't want to lose PG.  ET is reserved and should be always be 1*/
    paging_enabled = svm_paging_enabled(v);
    value |= X86_CR0_ET;
    vmcb->cr0 = value | X86_CR0_PG;
    v->arch.hvm_svm.cpu_shadow_cr0 = value;

    /* TS cleared? Then initialise FPU now. */
    if ( !(value & X86_CR0_TS) )
    {
        setup_fpu(v);
        vmcb->exception_intercepts &= ~EXCEPTION_BITMAP_NM;
    }

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx\n", value);

    if ((value & X86_CR0_PE) && (value & X86_CR0_PG) && !paging_enabled) 
    {
        /* The guest CR3 must be pointing to the guest physical. */
        if (!VALID_MFN(mfn = 
                       get_mfn_from_gpfn(v->arch.hvm_svm.cpu_cr3 >> PAGE_SHIFT))
            || !get_page(mfn_to_page(mfn), v->domain))
        {
            printk("Invalid CR3 value = %lx\n", v->arch.hvm_svm.cpu_cr3);
            domain_crash_synchronous(); /* need to take a clean path */
        }

#if defined(__x86_64__)
        if (test_bit(SVM_CPU_STATE_LME_ENABLED, &v->arch.hvm_svm.cpu_state) 
            && !test_bit(SVM_CPU_STATE_PAE_ENABLED, 
                         &v->arch.hvm_svm.cpu_state))
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enable\n");
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
        }

        if (test_bit(SVM_CPU_STATE_LME_ENABLED, &v->arch.hvm_svm.cpu_state))
        {
            /* Here the PAE is should to be opened */
            HVM_DBG_LOG(DBG_LEVEL_1, "Enable the Long mode\n");
            set_bit(SVM_CPU_STATE_LMA_ENABLED,
                    &v->arch.hvm_svm.cpu_state);
            vmcb->efer |= (EFER_LMA | EFER_LME);
        }
#endif  /* __x86_64__ */

        /* Now arch.guest_table points to machine physical. */
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = pagetable_from_pfn(mfn);
        if ( old_base_mfn )
            put_page(mfn_to_page(old_base_mfn));
        shadow_update_paging_modes(v);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx", 
                    (unsigned long) (mfn << PAGE_SHIFT));

        vmcb->cr3 = v->arch.hvm_vcpu.hw_cr3; 
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    }

    if ( !((value & X86_CR0_PE) && (value & X86_CR0_PG)) && paging_enabled )
        if ( v->arch.hvm_svm.cpu_cr3 ) {
            put_page(mfn_to_page(get_mfn_from_gpfn(
                v->arch.hvm_svm.cpu_cr3 >> PAGE_SHIFT)));
            v->arch.guest_table = pagetable_null();
        }

    /*
     * SVM implements paged real-mode and when we return to real-mode
     * we revert back to the physical mappings that the domain builder
     * created.
     */
    if ((value & X86_CR0_PE) == 0) {
        if (value & X86_CR0_PG) {
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            return 0;
        }
        shadow_update_paging_modes(v);
        vmcb->cr3 = v->arch.hvm_vcpu.hw_cr3;
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    }
    else if ( (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PE )
    {
        /* we should take care of this kind of situation */
        shadow_update_paging_modes(v);
        vmcb->cr3 = v->arch.hvm_vcpu.hw_cr3;
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    }

    return 1;
}

/*
 * Read from control registers. CR0 and CR4 are read from the shadow.
 */
static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value = 0;
    struct vcpu *v = current;
    struct vlapic *vlapic = VLAPIC(v);
    struct vmcb_struct *vmcb;

    vmcb = v->arch.hvm_svm.vmcb;
    ASSERT(vmcb);

    switch (cr)
    {
    case 0:
        value = v->arch.hvm_svm.cpu_shadow_cr0;
        if (svm_dbg_on)
            printk("CR0 read =%lx \n", value );
        break;
    case 2:
        value = vmcb->cr2;
        break;
    case 3:
        value = (unsigned long) v->arch.hvm_svm.cpu_cr3;
        if (svm_dbg_on)
            printk("CR3 read =%lx \n", value );
        break;
    case 4:
        value = (unsigned long) v->arch.hvm_svm.cpu_shadow_cr4;
        if (svm_dbg_on)
            printk( "CR4 read=%lx\n", value );
        break;
    case 8:
        value = (unsigned long)vlapic_get_reg(vlapic, APIC_TASKPRI);
        value = (value & 0xF0) >> 4;
        break;
        
    default:
        __hvm_bug(regs);
    }

    set_reg(gp, value, regs, vmcb);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "mov_from_cr: CR%d, value = %lx,", cr, value);
}


static inline int svm_pgbit_test(struct vcpu *v)
{
    return v->arch.hvm_svm.cpu_shadow_cr0 & X86_CR0_PG;
}


/*
 * Write to control registers
 */
static int mov_to_cr(int gpreg, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    unsigned long old_cr;
    struct vcpu *v = current;
    struct vlapic *vlapic = VLAPIC(v);
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);

    value = get_reg(gpreg, regs, vmcb);

    HVM_DBG_LOG(DBG_LEVEL_1, "mov_to_cr: CR%d, value = %lx,", cr, value);
    HVM_DBG_LOG(DBG_LEVEL_1, "current = %lx,", (unsigned long) current);

    switch (cr) 
    {
    case 0: 
        if (svm_dbg_on)
            printk("CR0 write =%lx \n", value );
        return svm_set_cr0(value);

    case 3: 
    {
        unsigned long old_base_mfn, mfn;
        if (svm_dbg_on)
            printk("CR3 write =%lx \n", value );
        /* If paging is not enabled yet, simply copy the value to CR3. */
        if (!svm_paging_enabled(v)) {
            v->arch.hvm_svm.cpu_cr3 = value;
            break;
        }
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);

        /* We make a new one if the shadow does not exist. */
        if (value == v->arch.hvm_svm.cpu_cr3) 
        {
            /* 
             * This is simple TLB flush, implying the guest has 
             * removed some translation or changed page attributes.
             * We simply invalidate the shadow.
             */
            mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT);
            if (mfn != pagetable_get_pfn(v->arch.guest_table))
                __hvm_bug(regs);
            shadow_update_cr3(v);
        }
        else 
        {
            /*
             * If different, make a shadow. Check if the PDBR is valid
             * first.
             */
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
            if (((value >> PAGE_SHIFT) > v->domain->max_pages) 
                || !VALID_MFN(mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT))
                || !get_page(mfn_to_page(mfn), v->domain))
            {
                printk("Invalid CR3 value=%lx\n", value);
                domain_crash_synchronous(); /* need to take a clean path */
            }

            old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
            v->arch.guest_table = pagetable_from_pfn(mfn);

            if (old_base_mfn)
                put_page(mfn_to_page(old_base_mfn));

            /*
             * arch.shadow_table should now hold the next CR3 for shadow
             */
            v->arch.hvm_svm.cpu_cr3 = value;
            update_cr3(v);
            vmcb->cr3 = v->arch.hvm_vcpu.hw_cr3; 
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx", value);
        }
        break;
    }

    case 4: /* CR4 */
    {
        if (svm_dbg_on)
            printk( "write cr4=%lx, cr0=%lx\n", 
                    value,  v->arch.hvm_svm.cpu_shadow_cr0 );
        old_cr = v->arch.hvm_svm.cpu_shadow_cr4;
        if ( value & X86_CR4_PAE && !(old_cr & X86_CR4_PAE) )
        {
            set_bit(SVM_CPU_STATE_PAE_ENABLED, &v->arch.hvm_svm.cpu_state);
            if ( svm_pgbit_test(v) )
            {
                /* The guest is a 32-bit PAE guest. */
#if CONFIG_PAGING_LEVELS >= 3
                unsigned long mfn, old_base_mfn;

                if ( !VALID_MFN(mfn = get_mfn_from_gpfn(
                    v->arch.hvm_svm.cpu_cr3 >> PAGE_SHIFT)) ||
                     !get_page(mfn_to_page(mfn), v->domain) )
                {
                    printk("Invalid CR3 value = %lx", v->arch.hvm_svm.cpu_cr3);
                    domain_crash_synchronous(); /* need to take a clean path */
                }

                /*
                 * Now arch.guest_table points to machine physical.
                 */

                old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
                v->arch.guest_table = pagetable_from_pfn(mfn);
                if ( old_base_mfn )
                    put_page(mfn_to_page(old_base_mfn));
                shadow_update_paging_modes(v);

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                            (unsigned long) (mfn << PAGE_SHIFT));

                vmcb->cr3 = v->arch.hvm_vcpu.hw_cr3; 

                /*
                 * arch->shadow_table should hold the next CR3 for shadow
                 */

                HVM_DBG_LOG(DBG_LEVEL_VMMU, 
                            "Update CR3 value = %lx, mfn = %lx",
                            v->arch.hvm_svm.cpu_cr3, mfn);
#endif
            }
        }
        else if (value & X86_CR4_PAE) {
            set_bit(SVM_CPU_STATE_PAE_ENABLED, &v->arch.hvm_svm.cpu_state);
        } else {
            if (test_bit(SVM_CPU_STATE_LMA_ENABLED,
                         &v->arch.hvm_svm.cpu_state)) {
                svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            }
            clear_bit(SVM_CPU_STATE_PAE_ENABLED, &v->arch.hvm_svm.cpu_state);
        }

        v->arch.hvm_svm.cpu_shadow_cr4 = value;
        vmcb->cr4 = value | SVM_CR4_HOST_MASK;
  
        /*
         * Writing to CR4 to modify the PSE, PGE, or PAE flag invalidates
         * all TLB entries except global entries.
         */
        if ((old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE))
        {
            set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
            shadow_update_paging_modes(v);
        }
        break;
    }

    case 8:
    {
        vlapic_set_reg(vlapic, APIC_TASKPRI, ((value & 0x0F) << 4));
        vlapic_update_ppr(vlapic);
        break;
    }

    default:
        printk("invalid cr: %d\n", cr);
        __hvm_bug(regs);
    }

    return 1;
}


#define ARR_SIZE(x) (sizeof(x) / sizeof(x[0]))


static int svm_cr_access(struct vcpu *v, unsigned int cr, unsigned int type,
                         struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int inst_len = 0;
    int index;
    unsigned int gpreg;
    unsigned long value;
    u8 buffer[MAX_INST_LEN];   
    u8 prefix = 0;
    int result = 1;
    enum instruction_index list_a[] = {INSTR_MOV2CR, INSTR_CLTS, INSTR_LMSW};
    enum instruction_index list_b[] = {INSTR_MOVCR2, INSTR_SMSW};
    enum instruction_index match;

    ASSERT(vmcb);

    inst_copy_from_guest(buffer, svm_rip2pointer(vmcb), sizeof(buffer));

    /* get index to first actual instruction byte - as we will need to know 
       where the prefix lives later on */
    index = skip_prefix_bytes(buffer, sizeof(buffer));
    
    if (type == TYPE_MOV_TO_CR) 
    {
        inst_len = __get_instruction_length_from_list(
            vmcb, list_a, ARR_SIZE(list_a), &buffer[index], &match);
    }
    else
    {
        inst_len = __get_instruction_length_from_list(
            vmcb, list_b, ARR_SIZE(list_b), &buffer[index], &match);
    }

    ASSERT(inst_len > 0);

    inst_len += index;

    /* Check for REX prefix - it's ALWAYS the last byte of any prefix bytes */
    if (index > 0 && (buffer[index-1] & 0xF0) == 0x40)
        prefix = buffer[index-1];

    HVM_DBG_LOG(DBG_LEVEL_1, "eip = %lx", (unsigned long) vmcb->rip);

    switch (match) 
    {
    case INSTR_MOV2CR:
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        result = mov_to_cr(gpreg, cr, regs);
        break;

    case INSTR_MOVCR2:
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        mov_from_cr(cr, gpreg, regs);
        break;

    case INSTR_CLTS:
        /* TS being cleared means that it's time to restore fpu state. */
        setup_fpu(current);
        vmcb->exception_intercepts &= ~EXCEPTION_BITMAP_NM;
        vmcb->cr0 &= ~X86_CR0_TS; /* clear TS */
        v->arch.hvm_svm.cpu_shadow_cr0 &= ~X86_CR0_TS; /* clear TS */
        break;

    case INSTR_LMSW:
        if (svm_dbg_on)
            svm_dump_inst(svm_rip2pointer(vmcb));
        
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        value = get_reg(gpreg, regs, vmcb) & 0xF;

        if (svm_dbg_on)
            printk("CR0-LMSW value=%lx, reg=%d, inst_len=%d\n", value, gpreg, 
                   inst_len);

        value = (v->arch.hvm_svm.cpu_shadow_cr0 & ~0xF) | value;

        if (svm_dbg_on)
            printk("CR0-LMSW CR0 - New value=%lx\n", value);

        result = svm_set_cr0(value);
        break;

    case INSTR_SMSW:
        if (svm_dbg_on)
            svm_dump_inst(svm_rip2pointer(vmcb));
        value = v->arch.hvm_svm.cpu_shadow_cr0;
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        set_reg(gpreg, value, regs, vmcb);

        if (svm_dbg_on)
            printk("CR0-SMSW value=%lx, reg=%d, inst_len=%d\n", value, gpreg, 
                   inst_len);
        break;

    default:
        __hvm_bug(regs);
        break;
    }

    ASSERT(inst_len);

    __update_guest_eip(vmcb, inst_len);
    
    return result;
}

static inline void svm_do_msr_access(
    struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int  inst_len;
    u64 msr_content=0;
    u32 eax, edx;

    ASSERT(vmcb);

    HVM_DBG_LOG(DBG_LEVEL_1, "svm_do_msr_access: ecx=%lx, eax=%lx, edx=%lx, "
                "exitinfo = %lx", (unsigned long)regs->ecx, 
                (unsigned long)regs->eax, (unsigned long)regs->edx, 
                (unsigned long)vmcb->exitinfo1);

    /* is it a read? */
    if (vmcb->exitinfo1 == 0)
    {
        inst_len = __get_instruction_length(vmcb, INSTR_RDMSR, NULL);

        regs->edx = 0;
        switch (regs->ecx) {
        case MSR_IA32_TIME_STAMP_COUNTER:
            msr_content = hvm_get_guest_time(v);
            break;
        case MSR_IA32_SYSENTER_CS:
            msr_content = vmcb->sysenter_cs;
            break;
        case MSR_IA32_SYSENTER_ESP: 
            msr_content = vmcb->sysenter_esp;
            break;
        case MSR_IA32_SYSENTER_EIP:     
            msr_content = vmcb->sysenter_eip;
            break;
        case MSR_IA32_APICBASE:
            msr_content = VLAPIC(v) ? VLAPIC(v)->apic_base_msr : 0;
            break;
        default:
            if (long_mode_do_msr_read(regs))
                goto done;

            if ( rdmsr_hypervisor_regs(regs->ecx, &eax, &edx) )
            {
                regs->eax = eax;
                regs->edx = edx;
                goto done;
            }

            rdmsr_safe(regs->ecx, regs->eax, regs->edx);
            break;
        }
        regs->eax = msr_content & 0xFFFFFFFF;
        regs->edx = msr_content >> 32;
    }
    else
    {
        inst_len = __get_instruction_length(vmcb, INSTR_WRMSR, NULL);
        msr_content = (regs->eax & 0xFFFFFFFF) | ((u64)regs->edx << 32);

        switch (regs->ecx)
        {
        case MSR_IA32_TIME_STAMP_COUNTER:
            hvm_set_guest_time(v, msr_content);
            break;
        case MSR_IA32_SYSENTER_CS:
            vmcb->sysenter_cs = msr_content;
            break;
        case MSR_IA32_SYSENTER_ESP: 
            vmcb->sysenter_esp = msr_content;
            break;
        case MSR_IA32_SYSENTER_EIP:     
            vmcb->sysenter_eip = msr_content;
            break;
        case MSR_IA32_APICBASE:
            vlapic_msr_set(VLAPIC(v), msr_content);
            break;
        default:
            if ( !long_mode_do_msr_write(regs) )
                wrmsr_hypervisor_regs(regs->ecx, regs->eax, regs->edx);
            break;
        }
    }

 done:

    HVM_DBG_LOG(DBG_LEVEL_1, "svm_do_msr_access returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);

    __update_guest_eip(vmcb, inst_len);
}


static inline void svm_vmexit_do_hlt(struct vmcb_struct *vmcb)
{
    __update_guest_eip(vmcb, 1);

    /* Check for interrupt not handled or new interrupt. */
    if ( (vmcb->rflags & X86_EFLAGS_IF) &&
         (vmcb->vintr.fields.irq || cpu_has_pending_irq(current)) )
        return;

    hvm_hlt(vmcb->rflags);
}


static void svm_vmexit_do_invd(struct vmcb_struct *vmcb)
{
    int  inst_len;
    
    /* Invalidate the cache - we can't really do that safely - maybe we should 
     * WBINVD, but I think it's just fine to completely ignore it - we should 
     * have cache-snooping that solves it anyways. -- Mats P. 
     */

    /* Tell the user that we did this - just in case someone runs some really 
     * weird operating system and wants to know why it's not working...
     */
    printk("INVD instruction intercepted - ignored\n");
    
    inst_len = __get_instruction_length(vmcb, INSTR_INVD, NULL);
    __update_guest_eip(vmcb, inst_len);
}    
        



#ifdef XEN_DEBUGGER
static void svm_debug_save_cpu_user_regs(struct vmcb_struct *vmcb, 
                                         struct cpu_user_regs *regs)
{
    regs->eip = vmcb->rip;
    regs->esp = vmcb->rsp;
    regs->eflags = vmcb->rflags;

    regs->xcs = vmcb->cs.sel;
    regs->xds = vmcb->ds.sel;
    regs->xes = vmcb->es.sel;
    regs->xfs = vmcb->fs.sel;
    regs->xgs = vmcb->gs.sel;
    regs->xss = vmcb->ss.sel;
}


static void svm_debug_restore_cpu_user_regs(struct cpu_user_regs *regs)
{
    vmcb->ss.sel   = regs->xss;
    vmcb->rsp      = regs->esp;
    vmcb->rflags   = regs->eflags;
    vmcb->cs.sel   = regs->xcs;
    vmcb->rip      = regs->eip;

    vmcb->gs.sel = regs->xgs;
    vmcb->fs.sel = regs->xfs;
    vmcb->es.sel = regs->xes;
    vmcb->ds.sel = regs->xds;
}
#endif


void svm_handle_invlpg(const short invlpga, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    u8 opcode[MAX_INST_LEN], prefix, length = MAX_INST_LEN;
    unsigned long g_vaddr;
    int inst_len;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);
    /* 
     * Unknown how many bytes the invlpg instruction will take.  Use the
     * maximum instruction length here
     */
    if (inst_copy_from_guest(opcode, svm_rip2pointer(vmcb), length) < length)
    {
        printk("svm_handle_invlpg (): Error reading memory %d bytes\n", 
               length);
        __hvm_bug(regs);
    }

    if (invlpga)
    {
        inst_len = __get_instruction_length(vmcb, INSTR_INVLPGA, opcode);
        ASSERT(inst_len > 0);
        __update_guest_eip(vmcb, inst_len);

        /* 
         * The address is implicit on this instruction. At the moment, we don't
         * use ecx (ASID) to identify individual guests pages 
         */
        g_vaddr = regs->eax;
    }
    else
    {
        /* What about multiple prefix codes? */
        prefix = (is_prefix(opcode[0])?opcode[0]:0);
        inst_len = __get_instruction_length(vmcb, INSTR_INVLPG, opcode);
        ASSERT(inst_len > 0);

        inst_len--;
        length -= inst_len;

        /* 
         * Decode memory operand of the instruction including ModRM, SIB, and
         * displacement to get effecticve address and length in bytes.  Assume
         * the system in either 32- or 64-bit mode.
         */
        g_vaddr = get_effective_addr_modrm64(vmcb, regs, prefix, 
                                             &opcode[inst_len], &length);

        inst_len += length;
        __update_guest_eip (vmcb, inst_len);
    }

    /* Overkill, we may not this */
    set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    shadow_invlpg(v, g_vaddr);
}


/*
 * Reset to realmode causes execution to start at 0xF000:0xFFF0 in
 * 16-bit realmode.  Basically, this mimics a processor reset.
 *
 * returns 0 on success, non-zero otherwise
 */
static int svm_do_vmmcall_reset_to_realmode(struct vcpu *v, 
                                            struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb;

    ASSERT(v);
    ASSERT(regs);

    vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);
    
    /* clear the vmcb and user regs */
    memset(regs, 0, sizeof(struct cpu_user_regs));
   
    /* VMCB Control */
    vmcb->tsc_offset = 0;

    /* VMCB State */
    vmcb->cr0 = X86_CR0_ET | X86_CR0_PG;
    v->arch.hvm_svm.cpu_shadow_cr0 = X86_CR0_ET;

    vmcb->cr2 = 0;
    vmcb->efer = EFER_SVME;

    vmcb->cr4 = SVM_CR4_HOST_MASK;
    v->arch.hvm_svm.cpu_shadow_cr4 = 0;
    clear_bit(SVM_CPU_STATE_PAE_ENABLED, &v->arch.hvm_svm.cpu_state);

    /* This will jump to ROMBIOS */
    vmcb->rip = 0xFFF0;

    /* setup the segment registers and all their hidden states */
    vmcb->cs.sel = 0xF000;
    vmcb->cs.attributes.bytes = 0x089b;
    vmcb->cs.limit = 0xffff;
    vmcb->cs.base = 0x000F0000;

    vmcb->ss.sel = 0x00;
    vmcb->ss.attributes.bytes = 0x0893;
    vmcb->ss.limit = 0xffff;
    vmcb->ss.base = 0x00;

    vmcb->ds.sel = 0x00;
    vmcb->ds.attributes.bytes = 0x0893;
    vmcb->ds.limit = 0xffff;
    vmcb->ds.base = 0x00;
    
    vmcb->es.sel = 0x00;
    vmcb->es.attributes.bytes = 0x0893;
    vmcb->es.limit = 0xffff;
    vmcb->es.base = 0x00;
    
    vmcb->fs.sel = 0x00;
    vmcb->fs.attributes.bytes = 0x0893;
    vmcb->fs.limit = 0xffff;
    vmcb->fs.base = 0x00;
    
    vmcb->gs.sel = 0x00;
    vmcb->gs.attributes.bytes = 0x0893;
    vmcb->gs.limit = 0xffff;
    vmcb->gs.base = 0x00;

    vmcb->ldtr.sel = 0x00;
    vmcb->ldtr.attributes.bytes = 0x0000;
    vmcb->ldtr.limit = 0x0;
    vmcb->ldtr.base = 0x00;

    vmcb->gdtr.sel = 0x00;
    vmcb->gdtr.attributes.bytes = 0x0000;
    vmcb->gdtr.limit = 0x0;
    vmcb->gdtr.base = 0x00;
    
    vmcb->tr.sel = 0;
    vmcb->tr.attributes.bytes = 0;
    vmcb->tr.limit = 0x0;
    vmcb->tr.base = 0;

    vmcb->idtr.sel = 0x00;
    vmcb->idtr.attributes.bytes = 0x0000;
    vmcb->idtr.limit = 0x3ff;
    vmcb->idtr.base = 0x00;

    vmcb->rax = 0;
    vmcb->rsp = 0;

    return 0;
}


/*
 * svm_do_vmmcall - SVM VMMCALL handler
 *
 * returns 0 on success, non-zero otherwise
 */
static int svm_do_vmmcall(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int inst_len;

    ASSERT(vmcb);
    ASSERT(regs);

    inst_len = __get_instruction_length(vmcb, INSTR_VMCALL, NULL);
    ASSERT(inst_len > 0);

    if ( regs->eax & 0x80000000 )
    {
        /* VMMCALL sanity check */
        if ( vmcb->cpl > get_vmmcall_cpl(regs->edi) )
        {
            printf("VMMCALL CPL check failed\n");
            return -1;
        }

        /* handle the request */
        switch ( regs->eax )
        {
        case VMMCALL_RESET_TO_REALMODE:
            if ( svm_do_vmmcall_reset_to_realmode(v, regs) )
            {
                printf("svm_do_vmmcall_reset_to_realmode() failed\n");
                return -1;
            }
            /* since we just reset the VMCB, return without adjusting
             * the eip */
            return 0;

        case VMMCALL_DEBUG:
            printf("DEBUG features not implemented yet\n");
            break;
        default:
            break;
        }

        hvm_print_line(v, regs->eax); /* provides the current domain */
    }
    else
    {
        hvm_do_hypercall(regs);
    }

    __update_guest_eip(vmcb, inst_len);
    return 0;
}


void svm_dump_inst(unsigned long eip)
{
    u8 opcode[256];
    unsigned long ptr;
    int len;
    int i;

    ptr = eip & ~0xff;
    len = 0;

    if (hvm_copy(opcode, ptr, sizeof(opcode), HVM_COPY_IN))
        len = sizeof(opcode);

    printf("Code bytes around(len=%d) %lx:", len, eip);
    for (i = 0; i < len; i++)
    {
        if ((i & 0x0f) == 0)
            printf("\n%08lx:", ptr+i);

        printf("%02x ", opcode[i]);
    }

    printf("\n");
}


void svm_dump_regs(const char *from, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long pt = pagetable_get_paddr(v->arch.shadow_table);

    printf("%s: guest registers from %s:\n", __func__, from);
#if defined (__x86_64__)
    printk("rax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, regs->rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           regs->r12, regs->r13, regs->r14);
    printk("r15: %016lx   cr0: %016lx   cr3: %016lx\n",
           regs->r15, v->arch.hvm_svm.cpu_shadow_cr0, vmcb->cr3);
#else
    printf("eax: %08x, ebx: %08x, ecx: %08x, edx: %08x\n", 
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printf("edi: %08x, esi: %08x, ebp: %08x, esp: %08x\n", 
           regs->edi, regs->esi, regs->ebp, regs->esp);
    printf("%s: guest cr0: %lx\n", __func__, 
           v->arch.hvm_svm.cpu_shadow_cr0);
    printf("guest CR3 = %llx\n", vmcb->cr3);
#endif
    printf("%s: pt = %lx\n", __func__, pt);
}


void svm_dump_host_regs(const char *from)
{
    struct vcpu *v = current;
    unsigned long pt = pt = pagetable_get_paddr(v->arch.monitor_table);
    unsigned long cr3, cr0;
    printf("Host registers at %s\n", from);

    __asm__ __volatile__ ("\tmov %%cr0,%0\n"
                          "\tmov %%cr3,%1\n"
                          : "=r" (cr0), "=r"(cr3));
    printf("%s: pt = %lx, cr3 = %lx, cr0 = %lx\n", __func__, pt, cr3, cr0);
}

#ifdef SVM_EXTRA_DEBUG
static char *exit_reasons[] = {
    [VMEXIT_CR0_READ] = "CR0_READ",
    [VMEXIT_CR1_READ] = "CR1_READ",
    [VMEXIT_CR2_READ] = "CR2_READ",
    [VMEXIT_CR3_READ] = "CR3_READ",
    [VMEXIT_CR4_READ] = "CR4_READ",
    [VMEXIT_CR5_READ] = "CR5_READ",
    [VMEXIT_CR6_READ] = "CR6_READ",
    [VMEXIT_CR7_READ] = "CR7_READ",
    [VMEXIT_CR8_READ] = "CR8_READ",
    [VMEXIT_CR9_READ] = "CR9_READ",
    [VMEXIT_CR10_READ] = "CR10_READ",
    [VMEXIT_CR11_READ] = "CR11_READ",
    [VMEXIT_CR12_READ] = "CR12_READ",
    [VMEXIT_CR13_READ] = "CR13_READ",
    [VMEXIT_CR14_READ] = "CR14_READ",
    [VMEXIT_CR15_READ] = "CR15_READ",
    [VMEXIT_CR0_WRITE] = "CR0_WRITE",
    [VMEXIT_CR1_WRITE] = "CR1_WRITE",
    [VMEXIT_CR2_WRITE] = "CR2_WRITE",
    [VMEXIT_CR3_WRITE] = "CR3_WRITE",
    [VMEXIT_CR4_WRITE] = "CR4_WRITE",
    [VMEXIT_CR5_WRITE] = "CR5_WRITE",
    [VMEXIT_CR6_WRITE] = "CR6_WRITE",
    [VMEXIT_CR7_WRITE] = "CR7_WRITE",
    [VMEXIT_CR8_WRITE] = "CR8_WRITE",
    [VMEXIT_CR9_WRITE] = "CR9_WRITE",
    [VMEXIT_CR10_WRITE] = "CR10_WRITE",
    [VMEXIT_CR11_WRITE] = "CR11_WRITE",
    [VMEXIT_CR12_WRITE] = "CR12_WRITE",
    [VMEXIT_CR13_WRITE] = "CR13_WRITE",
    [VMEXIT_CR14_WRITE] = "CR14_WRITE",
    [VMEXIT_CR15_WRITE] = "CR15_WRITE",
    [VMEXIT_DR0_READ] = "DR0_READ",
    [VMEXIT_DR1_READ] = "DR1_READ",
    [VMEXIT_DR2_READ] = "DR2_READ",
    [VMEXIT_DR3_READ] = "DR3_READ",
    [VMEXIT_DR4_READ] = "DR4_READ",
    [VMEXIT_DR5_READ] = "DR5_READ",
    [VMEXIT_DR6_READ] = "DR6_READ",
    [VMEXIT_DR7_READ] = "DR7_READ",
    [VMEXIT_DR8_READ] = "DR8_READ",
    [VMEXIT_DR9_READ] = "DR9_READ",
    [VMEXIT_DR10_READ] = "DR10_READ",
    [VMEXIT_DR11_READ] = "DR11_READ",
    [VMEXIT_DR12_READ] = "DR12_READ",
    [VMEXIT_DR13_READ] = "DR13_READ",
    [VMEXIT_DR14_READ] = "DR14_READ",
    [VMEXIT_DR15_READ] = "DR15_READ",
    [VMEXIT_DR0_WRITE] = "DR0_WRITE",
    [VMEXIT_DR1_WRITE] = "DR1_WRITE",
    [VMEXIT_DR2_WRITE] = "DR2_WRITE",
    [VMEXIT_DR3_WRITE] = "DR3_WRITE",
    [VMEXIT_DR4_WRITE] = "DR4_WRITE",
    [VMEXIT_DR5_WRITE] = "DR5_WRITE",
    [VMEXIT_DR6_WRITE] = "DR6_WRITE",
    [VMEXIT_DR7_WRITE] = "DR7_WRITE",
    [VMEXIT_DR8_WRITE] = "DR8_WRITE",
    [VMEXIT_DR9_WRITE] = "DR9_WRITE",
    [VMEXIT_DR10_WRITE] = "DR10_WRITE",
    [VMEXIT_DR11_WRITE] = "DR11_WRITE",
    [VMEXIT_DR12_WRITE] = "DR12_WRITE",
    [VMEXIT_DR13_WRITE] = "DR13_WRITE",
    [VMEXIT_DR14_WRITE] = "DR14_WRITE",
    [VMEXIT_DR15_WRITE] = "DR15_WRITE",
    [VMEXIT_EXCEPTION_DE] = "EXCEPTION_DE",
    [VMEXIT_EXCEPTION_DB] = "EXCEPTION_DB",
    [VMEXIT_EXCEPTION_NMI] = "EXCEPTION_NMI",
    [VMEXIT_EXCEPTION_BP] = "EXCEPTION_BP",
    [VMEXIT_EXCEPTION_OF] = "EXCEPTION_OF",
    [VMEXIT_EXCEPTION_BR] = "EXCEPTION_BR",
    [VMEXIT_EXCEPTION_UD] = "EXCEPTION_UD",
    [VMEXIT_EXCEPTION_NM] = "EXCEPTION_NM",
    [VMEXIT_EXCEPTION_DF] = "EXCEPTION_DF",
    [VMEXIT_EXCEPTION_09] = "EXCEPTION_09",
    [VMEXIT_EXCEPTION_TS] = "EXCEPTION_TS",
    [VMEXIT_EXCEPTION_NP] = "EXCEPTION_NP",
    [VMEXIT_EXCEPTION_SS] = "EXCEPTION_SS",
    [VMEXIT_EXCEPTION_GP] = "EXCEPTION_GP",
    [VMEXIT_EXCEPTION_PF] = "EXCEPTION_PF",
    [VMEXIT_EXCEPTION_15] = "EXCEPTION_15",
    [VMEXIT_EXCEPTION_MF] = "EXCEPTION_MF",
    [VMEXIT_EXCEPTION_AC] = "EXCEPTION_AC",
    [VMEXIT_EXCEPTION_MC] = "EXCEPTION_MC",
    [VMEXIT_EXCEPTION_XF] = "EXCEPTION_XF",
    [VMEXIT_INTR] = "INTR",
    [VMEXIT_NMI] = "NMI",
    [VMEXIT_SMI] = "SMI",
    [VMEXIT_INIT] = "INIT",
    [VMEXIT_VINTR] = "VINTR",
    [VMEXIT_CR0_SEL_WRITE] = "CR0_SEL_WRITE",
    [VMEXIT_IDTR_READ] = "IDTR_READ",
    [VMEXIT_GDTR_READ] = "GDTR_READ",
    [VMEXIT_LDTR_READ] = "LDTR_READ",
    [VMEXIT_TR_READ] = "TR_READ",
    [VMEXIT_IDTR_WRITE] = "IDTR_WRITE",
    [VMEXIT_GDTR_WRITE] = "GDTR_WRITE",
    [VMEXIT_LDTR_WRITE] = "LDTR_WRITE",
    [VMEXIT_TR_WRITE] = "TR_WRITE",
    [VMEXIT_RDTSC] = "RDTSC",
    [VMEXIT_RDPMC] = "RDPMC",
    [VMEXIT_PUSHF] = "PUSHF",
    [VMEXIT_POPF] = "POPF",
    [VMEXIT_CPUID] = "CPUID",
    [VMEXIT_RSM] = "RSM",
    [VMEXIT_IRET] = "IRET",
    [VMEXIT_SWINT] = "SWINT",
    [VMEXIT_INVD] = "INVD",
    [VMEXIT_PAUSE] = "PAUSE",
    [VMEXIT_HLT] = "HLT",
    [VMEXIT_INVLPG] = "INVLPG",
    [VMEXIT_INVLPGA] = "INVLPGA",
    [VMEXIT_IOIO] = "IOIO",
    [VMEXIT_MSR] = "MSR",
    [VMEXIT_TASK_SWITCH] = "TASK_SWITCH",
    [VMEXIT_FERR_FREEZE] = "FERR_FREEZE",
    [VMEXIT_SHUTDOWN] = "SHUTDOWN",
    [VMEXIT_VMRUN] = "VMRUN",
    [VMEXIT_VMMCALL] = "VMMCALL",
    [VMEXIT_VMLOAD] = "VMLOAD",
    [VMEXIT_VMSAVE] = "VMSAVE",
    [VMEXIT_STGI] = "STGI",
    [VMEXIT_CLGI] = "CLGI",
    [VMEXIT_SKINIT] = "SKINIT",
    [VMEXIT_RDTSCP] = "RDTSCP",
    [VMEXIT_ICEBP] = "ICEBP",
    [VMEXIT_NPF] = "NPF"
};
#endif /* SVM_EXTRA_DEBUG */

#ifdef SVM_WALK_GUEST_PAGES
void walk_shadow_and_guest_pt(unsigned long gva)
{
    l2_pgentry_t gpde;
    l2_pgentry_t spde;
    l1_pgentry_t gpte;
    l1_pgentry_t spte;
    struct vcpu        *v    = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long gpa;

    gpa = shadow_gva_to_gpa(current, gva);
    printk( "gva = %lx, gpa=%lx, gCR3=%x\n", gva, gpa, (u32)vmcb->cr3 );
    if( !svm_paging_enabled(v) || mmio_space(gpa) )
        return;

    /* let's dump the guest and shadow page info */

    __guest_get_l2e(v, gva, &gpde);
    printk( "G-PDE = %x, flags=%x\n", gpde.l2, l2e_get_flags(gpde) );
    __shadow_get_l2e( v, gva, &spde );
    printk( "S-PDE = %x, flags=%x\n", spde.l2, l2e_get_flags(spde) );

    if ( unlikely(!(l2e_get_flags(gpde) & _PAGE_PRESENT)) )
        return;

    spte = l1e_empty();

    /* This is actually overkill - we only need to ensure the hl2 is in-sync.*/
    shadow_sync_va(v, gva);

    gpte.l1 = 0;
    __copy_from_user(&gpte, &linear_pg_table[ l1_linear_offset(gva) ],
                     sizeof(gpte) );
    printk( "G-PTE = %x, flags=%x\n", gpte.l1, l1e_get_flags(gpte) );

    BUG(); // need to think about this, and convert usage of
    // phys_to_machine_mapping to use pagetable format...
    __copy_from_user( &spte, &phys_to_machine_mapping[ l1e_get_pfn( gpte ) ], 
                      sizeof(spte) );

    printk( "S-PTE = %x, flags=%x\n", spte.l1, l1e_get_flags(spte));
}
#endif /* SVM_WALK_GUEST_PAGES */




asmlinkage void svm_vmexit_handler(struct cpu_user_regs regs)
{
    unsigned int exit_reason;
    unsigned long eip;
    struct vcpu *v = current;
    int error;
    int do_debug = 0;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);

    exit_reason = vmcb->exitcode;
    save_svm_cpu_user_regs(v, &regs);

    vmcb->tlb_control = 1;


    if (exit_reason == VMEXIT_INVALID)
    {
        svm_dump_vmcb(__func__, vmcb);
        domain_crash_synchronous();
    }

#ifdef SVM_EXTRA_DEBUG
    {
#if defined(__i386__)
#define rip eip
#endif

        static unsigned long intercepts_counter = 0;

        if (svm_dbg_on && exit_reason == VMEXIT_EXCEPTION_PF) 
        {
            if (svm_paging_enabled(v) && 
                !mmio_space(shadow_gva_to_gpa(current, vmcb->exitinfo2)))
            {
                printk("I%08ld,ExC=%s(%d),IP=%x:%llx,"
                       "I1=%llx,I2=%llx,INT=%llx, "
                       "gpa=%llx\n", intercepts_counter,
                       exit_reasons[exit_reason], exit_reason, regs.cs,
                       (unsigned long long) regs.rip,
                       (unsigned long long) vmcb->exitinfo1,
                       (unsigned long long) vmcb->exitinfo2,
                       (unsigned long long) vmcb->exitintinfo.bytes,
                       (unsigned long long) shadow_gva_to_gpa(current, vmcb->exitinfo2));
            }
            else 
            {
                printk("I%08ld,ExC=%s(%d),IP=%x:%llx,"
                       "I1=%llx,I2=%llx,INT=%llx\n", 
                       intercepts_counter,
                       exit_reasons[exit_reason], exit_reason, regs.cs,
                       (unsigned long long) regs.rip,
                       (unsigned long long) vmcb->exitinfo1,
                       (unsigned long long) vmcb->exitinfo2,
                       (unsigned long long) vmcb->exitintinfo.bytes );
            }
        } 
        else if ( svm_dbg_on 
                  && exit_reason != VMEXIT_IOIO 
                  && exit_reason != VMEXIT_INTR) 
        {

            if (exit_reasons[exit_reason])
            {
                printk("I%08ld,ExC=%s(%d),IP=%x:%llx,"
                       "I1=%llx,I2=%llx,INT=%llx\n", 
                       intercepts_counter,
                       exit_reasons[exit_reason], exit_reason, regs.cs,
                       (unsigned long long) regs.rip,
                       (unsigned long long) vmcb->exitinfo1,
                       (unsigned long long) vmcb->exitinfo2,
                       (unsigned long long) vmcb->exitintinfo.bytes);
            } 
            else 
            {
                printk("I%08ld,ExC=%d(0x%x),IP=%x:%llx,"
                       "I1=%llx,I2=%llx,INT=%llx\n", 
                       intercepts_counter, exit_reason, exit_reason, regs.cs, 
                       (unsigned long long) regs.rip,
                       (unsigned long long) vmcb->exitinfo1,
                       (unsigned long long) vmcb->exitinfo2,
                       (unsigned long long) vmcb->exitintinfo.bytes);
            }
        }

#ifdef SVM_WALK_GUEST_PAGES
        if( exit_reason == VMEXIT_EXCEPTION_PF 
            && ( ( vmcb->exitinfo2 == vmcb->rip )
                 || vmcb->exitintinfo.bytes) )
        {
            if ( svm_paging_enabled(v) &&
                 !mmio_space(gva_to_gpa(vmcb->exitinfo2)) )
                walk_shadow_and_guest_pt(vmcb->exitinfo2);
        }
#endif

        intercepts_counter++;

#if 0
        if (svm_dbg_on)
            do_debug = svm_do_debugout(exit_reason);
#endif

        if (do_debug)
        {
            printk("%s:+ guest_table = 0x%08x, monitor_table = 0x%08x, "
                   "shadow_table = 0x%08x\n", 
                   __func__,
                   (int) v->arch.guest_table.pfn,
                   (int) v->arch.monitor_table.pfn, 
                   (int) v->arch.shadow_table.pfn);

            svm_dump_vmcb(__func__, vmcb);
            svm_dump_regs(__func__, &regs);
            svm_dump_inst(svm_rip2pointer(vmcb));
        }

#if defined(__i386__)
#undef rip
#endif

    }
#endif /* SVM_EXTRA_DEBUG */


    perfc_incra(svmexits, exit_reason);
    eip = vmcb->rip;

#ifdef SVM_EXTRA_DEBUG
    if (do_debug)
    {
        printk("eip = %lx, exit_reason = %d (0x%x)\n", 
               eip, exit_reason, exit_reason);
    }
#endif /* SVM_EXTRA_DEBUG */

    TRACE_3D(TRC_VMX_VMEXIT, v->domain->domain_id, eip, exit_reason);

    switch (exit_reason) 
    {
    case VMEXIT_EXCEPTION_DB:
    {
#ifdef XEN_DEBUGGER
        svm_debug_save_cpu_user_regs(&regs);
        pdb_handle_exception(1, &regs, 1);
        svm_debug_restore_cpu_user_regs(&regs);
#else
        svm_store_cpu_user_regs(&regs, v);
        domain_pause_for_debugger();  
#endif
    }
    break;

    case VMEXIT_NMI:
        do_nmi(&regs, 0);
        break;

    case VMEXIT_SMI:
        /*
         * For asynchronous SMI's, we just need to allow global interrupts 
         * so that the SMI is taken properly in the context of the host.  The
         * standard code does a STGI after the VMEXIT which should accomplish 
         * this task.  Continue as normal and restart the guest.
         */
        break;

    case VMEXIT_INIT:
        /*
         * Nothing to do, in fact we should never get to this point. 
         */
        break;

    case VMEXIT_EXCEPTION_BP:
#ifdef XEN_DEBUGGER
        svm_debug_save_cpu_user_regs(&regs);
        pdb_handle_exception(3, &regs, 1);
        svm_debug_restore_cpu_user_regs(&regs);
#else
        if ( test_bit(_DOMF_debugging, &v->domain->domain_flags) )
            domain_pause_for_debugger();
        else 
            svm_inject_exception(v, TRAP_int3, 0, 0);
#endif
        break;

    case VMEXIT_EXCEPTION_NM:
        svm_do_no_device_fault(vmcb);
        break;  

    case VMEXIT_EXCEPTION_GP:
        /* This should probably not be trapped in the future */
        regs.error_code = vmcb->exitinfo1;
        svm_do_general_protection_fault(v, &regs);
        break;  

    case VMEXIT_EXCEPTION_PF:
    {
        unsigned long va;
        va = vmcb->exitinfo2;
        regs.error_code = vmcb->exitinfo1;
        HVM_DBG_LOG(DBG_LEVEL_VMMU, 
                    "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                    (unsigned long)regs.eax, (unsigned long)regs.ebx,
                    (unsigned long)regs.ecx, (unsigned long)regs.edx,
                    (unsigned long)regs.esi, (unsigned long)regs.edi);

        if (!(error = svm_do_page_fault(va, &regs))) 
        {
            /* Inject #PG using Interruption-Information Fields */
            svm_inject_exception(v, TRAP_page_fault, 1, regs.error_code);

            v->arch.hvm_svm.cpu_cr2 = va;
            vmcb->cr2 = va;
            TRACE_3D(TRC_VMX_INT, v->domain->domain_id, 
                     VMEXIT_EXCEPTION_PF, va);
        }
        break;
    }

    case VMEXIT_EXCEPTION_DF:
        /* Debug info to hopefully help debug WHY the guest double-faulted. */
        svm_dump_vmcb(__func__, vmcb);
        svm_dump_regs(__func__, &regs);
        svm_dump_inst(svm_rip2pointer(vmcb));
        svm_inject_exception(v, TRAP_double_fault, 1, 0);
        break;

    case VMEXIT_INTR:
        break;

    case VMEXIT_INVD:
        svm_vmexit_do_invd(vmcb);
        break;

    case VMEXIT_GDTR_WRITE:
        printk("WRITE to GDTR\n");
        break;

    case VMEXIT_TASK_SWITCH:
        __hvm_bug(&regs);
        break;

    case VMEXIT_CPUID:
        svm_vmexit_do_cpuid(vmcb, regs.eax, &regs);
        break;

    case VMEXIT_HLT:
        svm_vmexit_do_hlt(vmcb);
        break;

    case VMEXIT_INVLPG:
        svm_handle_invlpg(0, &regs);
        break;

    case VMEXIT_INVLPGA:
        svm_handle_invlpg(1, &regs);
        break;

    case VMEXIT_VMMCALL:
        svm_do_vmmcall(v, &regs);
        break;

    case VMEXIT_CR0_READ:
        svm_cr_access(v, 0, TYPE_MOV_FROM_CR, &regs);
        break;

    case VMEXIT_CR2_READ:
        svm_cr_access(v, 2, TYPE_MOV_FROM_CR, &regs);
        break;

    case VMEXIT_CR3_READ:
        svm_cr_access(v, 3, TYPE_MOV_FROM_CR, &regs);
        break;

    case VMEXIT_CR4_READ:
        svm_cr_access(v, 4, TYPE_MOV_FROM_CR, &regs);
        break;

    case VMEXIT_CR8_READ:
        svm_cr_access(v, 8, TYPE_MOV_FROM_CR, &regs);
        break;

    case VMEXIT_CR0_WRITE:
        svm_cr_access(v, 0, TYPE_MOV_TO_CR, &regs);
        break;

    case VMEXIT_CR2_WRITE:
        svm_cr_access(v, 2, TYPE_MOV_TO_CR, &regs);
        break;

    case VMEXIT_CR3_WRITE:
        svm_cr_access(v, 3, TYPE_MOV_TO_CR, &regs);
        local_flush_tlb();
        break;

    case VMEXIT_CR4_WRITE:
        svm_cr_access(v, 4, TYPE_MOV_TO_CR, &regs);
        break;

    case VMEXIT_CR8_WRITE:
        svm_cr_access(v, 8, TYPE_MOV_TO_CR, &regs);
        break;
	
    case VMEXIT_DR0_WRITE ... VMEXIT_DR7_WRITE:
        svm_dr_access(v, &regs);
        break;

    case VMEXIT_IOIO:
        svm_io_instruction(v);
        break;

    case VMEXIT_MSR:
        svm_do_msr_access(v, &regs);
        break;

    case VMEXIT_SHUTDOWN:
        printk("Guest shutdown exit\n");
        domain_crash_synchronous();
        break;

    default:
        printk("unexpected VMEXIT: exit reason = 0x%x, exitinfo1 = %llx, "
               "exitinfo2 = %llx\n", exit_reason, 
               (unsigned long long)vmcb->exitinfo1, 
               (unsigned long long)vmcb->exitinfo2);
        __hvm_bug(&regs);       /* should not happen */
        break;
    }

#ifdef SVM_EXTRA_DEBUG
    if (do_debug) 
    {
        printk("%s: Done switch on vmexit_code\n", __func__);
        svm_dump_regs(__func__, &regs);
    }

    if (do_debug) 
    {
        printk("vmexit_handler():- guest_table = 0x%08x, "
               "monitor_table = 0x%08x, shadow_table = 0x%08x\n",
               (int)v->arch.guest_table.pfn,
               (int)v->arch.monitor_table.pfn, 
               (int)v->arch.shadow_table.pfn);
        printk("svm_vmexit_handler: Returning\n");
    }
#endif

    return;
}

asmlinkage void svm_load_cr2(void)
{
    struct vcpu *v = current;

    local_irq_disable();
    asm volatile("mov %0,%%cr2": :"r" (v->arch.hvm_svm.cpu_cr2));
}

asmlinkage void svm_asid(void)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    /*
     * if need to assign new asid, or if switching cores,
     * retire asid for the old core, and assign a new asid to the current core.
     */
    if ( test_bit( ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags ) ||
         ( v->arch.hvm_svm.asid_core != v->arch.hvm_svm.launch_core )) {
        /* recycle asid */
        if ( !asidpool_assign_next(vmcb, 1,
                                   v->arch.hvm_svm.asid_core,
                                   v->arch.hvm_svm.launch_core) )
        {
            /* If we get here, we have a major problem */
            domain_crash_synchronous();
        }

        v->arch.hvm_svm.asid_core = v->arch.hvm_svm.launch_core;
        clear_bit( ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags );
    }
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
