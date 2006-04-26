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
#include <asm/shadow.h>
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>
#endif
#include <public/sched.h>
#include <public/hvm/ioreq.h>

#define SVM_EXTRA_DEBUG

#ifdef TRACE_BUFFER
static unsigned long trace_values[NR_CPUS][4];
#define TRACE_VMEXIT(index,value) trace_values[current->processor][index]=value
#else
#define TRACE_VMEXIT(index,value) ((void)0)
#endif

/* Useful define */
#define MAX_INST_SIZE  15

/* 
 * External functions, etc. We should move these to some suitable header file(s) */

extern void do_nmi(struct cpu_user_regs *, unsigned long);
extern int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip,
                                int inst_len);
extern asmlinkage void do_IRQ(struct cpu_user_regs *);
extern void send_pio_req(struct cpu_user_regs *regs, unsigned long port,
       unsigned long count, int size, long value, int dir, int pvalid);
extern int svm_instrlen(struct cpu_user_regs *regs, int mode);
extern void svm_dump_inst(unsigned long eip);
extern int svm_dbg_on;
void svm_manual_event_injection32(struct vcpu *v, struct cpu_user_regs *regs, 
        int vector, int has_code);
void svm_dump_regs(const char *from, struct cpu_user_regs *regs);

static void svm_relinquish_guest_resources(struct domain *d);

static struct asid_pool ASIDpool[NR_CPUS];

/*
 * Initializes the POOL of ASID used by the guests per core.
 */
void asidpool_init( int core )
{
    int i;
    ASIDpool[core].asid_lock = SPIN_LOCK_UNLOCKED;
    spin_lock(&ASIDpool[core].asid_lock);
    /* Host ASID is always in use */
    ASIDpool[core].asid[INITIAL_ASID] = ASID_INUSE;
    for( i=1; i<ASID_MAX; i++ )
    {
       ASIDpool[core].asid[i] = ASID_AVAILABLE;
    }
    spin_unlock(&ASIDpool[core].asid_lock);
}


/* internal function to get the next available ASID */
static int asidpool_fetch_next( struct vmcb_struct *vmcb, int core )
{
    int i;   
    for( i = 1; i < ASID_MAX; i++ )
    {
        if( ASIDpool[core].asid[i] == ASID_AVAILABLE )
        {
            vmcb->guest_asid = i;
            ASIDpool[core].asid[i] = ASID_INUSE;
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

    spin_lock(&ASIDpool[oldcore].asid_lock);
    if( retire_current && vmcb->guest_asid ) {
       ASIDpool[oldcore].asid[ vmcb->guest_asid & (ASID_MAX-1) ] = ASID_RETIRED;
    }
    spin_unlock(&ASIDpool[oldcore].asid_lock);
    spin_lock(&ASIDpool[newcore].asid_lock);
    if( asidpool_fetch_next( vmcb, newcore ) < 0 ) {
        if (svm_dbg_on)
            printk( "SVM: tlb(%ld)\n", cnt++ );
        /* FLUSH the TLB and all retired slots are made available */ 
        vmcb->tlb_control = 1;
        for( i = 1; i < ASID_MAX; i++ ) {
            if( ASIDpool[newcore].asid[i] == ASID_RETIRED ) {
                ASIDpool[newcore].asid[i] = ASID_AVAILABLE;
            }
        }
        /* Get the First slot available */ 
        res = asidpool_fetch_next( vmcb, newcore ) > 0;
    }
    spin_unlock(&ASIDpool[newcore].asid_lock);
    return res;
}

void asidpool_retire( struct vmcb_struct *vmcb, int core )
{
   spin_lock(&ASIDpool[core].asid_lock);
   if( vmcb->guest_asid ) {
       ASIDpool[core].asid[ vmcb->guest_asid & (ASID_MAX-1) ] = ASID_RETIRED;
   }
   spin_unlock(&ASIDpool[core].asid_lock);
}

static inline void svm_inject_exception(struct vmcb_struct *vmcb, 
                                        int trap, int ev, int error_code)
{
    eventinj_t event;

    event.bytes = 0;            
    event.fields.v = 1;
    event.fields.type = EVENTTYPE_EXCEPTION;
    event.fields.vector = trap;
    event.fields.ev = ev;
    event.fields.errorcode = error_code;

    ASSERT(vmcb->eventinj.fields.v == 0);
    
    vmcb->eventinj = event;
}

void stop_svm(void)
{
    u32 eax, edx;    

    /* We turn off the EFER_SVME bit. */
    rdmsr(MSR_EFER, eax, edx);
    eax &= ~EFER_SVME;
    wrmsr(MSR_EFER, eax, edx);

    printk("AMD SVM Extension is disabled.\n");
}

int svm_initialize_guest_resources(struct vcpu *v)
{
    svm_final_setup_guest(v);
    return 1;
}

static void svm_store_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *regs, unsigned long *crs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( regs != NULL )
    {
#if defined (__x86_64__)
        regs->rip    = vmcb->rip;
        regs->rsp    = vmcb->rsp;
        regs->rflags = vmcb->rflags;
        regs->cs     = vmcb->cs.sel;
        regs->ds     = vmcb->ds.sel;
        regs->es     = vmcb->es.sel;
        regs->ss     = vmcb->ss.sel;
        regs->gs     = vmcb->gs.sel;
        regs->fs     = vmcb->fs.sel;
#elif defined (__i386__)
        regs->eip    = vmcb->rip;
        regs->esp    = vmcb->rsp;
        regs->eflags = vmcb->rflags;
        regs->cs     = vmcb->cs.sel;
        regs->ds     = vmcb->ds.sel;
        regs->es     = vmcb->es.sel;
        regs->ss     = vmcb->ss.sel;
        regs->gs     = vmcb->gs.sel;
        regs->fs     = vmcb->fs.sel;
#endif
    }

    if ( crs != NULL )
    {
        crs[0] = vmcb->cr0;
        crs[3] = vmcb->cr3;
        crs[4] = vmcb->cr4;
    }
}

static void svm_load_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *regs)
{
    svm_load_cpu_user_regs(v, regs);
}

#define IS_CANO_ADDRESS(add) 1

static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *vc = current;
    //    struct svm_msr_state *msr = &vc->arch.hvm_svm.msr_content;
    struct vmcb_struct *vmcb = vc->arch.hvm_svm.vmcb;

    switch (regs->ecx)
    {
    case MSR_EFER:
        // msr_content = msr->msr_items[SVM_INDEX_MSR_EFER];
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
            svm_inject_exception(vmcb, TRAP_gp_fault, 1, 0);
            return 0;
        }

        /* LME: 0 -> 1 */
        if ( msr_content & EFER_LME &&
             !test_bit(SVM_CPU_STATE_LME_ENABLED, &vc->arch.hvm_svm.cpu_state) )
        {
            if ( svm_paging_enabled(vc) ||
                 !test_bit(SVM_CPU_STATE_PAE_ENABLED,
                           &vc->arch.hvm_svm.cpu_state) )
            {
                printk("trying to set LME bit when "
                       "in paging mode or PAE bit is not set\n");
                svm_inject_exception(vmcb, TRAP_gp_fault, 1, 0);
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
            svm_inject_exception(vmcb, TRAP_gp_fault, 1, 0);
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

int svm_realmode(struct vcpu *v)
{
    unsigned long cr0 = v->arch.hvm_svm.cpu_shadow_cr0;
    unsigned long eflags = v->arch.hvm_svm.vmcb->rflags;

    return (eflags & X86_EFLAGS_VM) || !(cr0 & X86_CR0_PE);
}

int svm_instruction_length(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long cr0 = vmcb->cr0, eflags = vmcb->rflags, mode;
    /* check which operating mode the guest is running */
    if( vmcb->efer & EFER_LMA )
        mode = vmcb->cs.attributes.fields.l ? 8 : 4;
    else
        mode = (eflags & X86_EFLAGS_VM) || !(cr0 & X86_CR0_PE) ? 2 : 4;
    return svm_instrlen(guest_cpu_user_regs(), mode);
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
    default:
        BUG();
    }
    return 0;                   /* dummy */
}

int start_svm(void)
{
    u32 eax, ecx, edx;
    
    /* Xen does not fill x86_capability words except 0. */
    ecx = cpuid_ecx(0x80000001);
    boot_cpu_data.x86_capability[5] = ecx;
    
    if (!(test_bit(X86_FEATURE_SVME, &boot_cpu_data.x86_capability)))
        return 0;
    
    rdmsr(MSR_EFER, eax, edx);
    eax |= EFER_SVME;
    wrmsr(MSR_EFER, eax, edx);
    asidpool_init(smp_processor_id());    
    printk("AMD SVM Extension is enabled for cpu %d.\n", smp_processor_id());
    
    /* Setup HVM interfaces */
    hvm_funcs.disable = stop_svm;

    hvm_funcs.initialize_guest_resources = svm_initialize_guest_resources;
    hvm_funcs.relinquish_guest_resources = svm_relinquish_guest_resources;

    hvm_funcs.store_cpu_guest_regs = svm_store_cpu_guest_regs;
    hvm_funcs.load_cpu_guest_regs = svm_load_cpu_guest_regs;

    hvm_funcs.realmode = svm_realmode;
    hvm_funcs.paging_enabled = svm_paging_enabled;
    hvm_funcs.instruction_length = svm_instruction_length;
    hvm_funcs.get_guest_ctrl_reg = svm_get_ctrl_reg;

    hvm_enabled = 1;    

    return 1;
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


void save_svm_cpu_user_regs(struct vcpu *v, struct cpu_user_regs *ctxt)
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

#if defined (__x86_64__)
void svm_store_cpu_user_regs(struct cpu_user_regs *regs, struct vcpu *v )
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    regs->rip    = vmcb->rip;
    regs->rsp    = vmcb->rsp;
    regs->rflags = vmcb->rflags;
    regs->cs     = vmcb->cs.sel;
    regs->ds     = vmcb->ds.sel;
    regs->es     = vmcb->es.sel;
    regs->ss     = vmcb->ss.sel;
}
#elif defined (__i386__)
void svm_store_cpu_user_regs(struct cpu_user_regs *regs, struct vcpu *v)
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
#endif

/* XXX Use svm_load_cpu_guest_regs instead */
#if defined (__i386__)
void svm_load_cpu_user_regs(struct vcpu *v, struct cpu_user_regs *regs)
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
#else /* (__i386__) */
void svm_load_cpu_user_regs(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 *intercepts = &v->arch.hvm_svm.vmcb->exception_intercepts;
    
    /* Write the guest register value into VMCB */
    vmcb->rax      = regs->rax;
    vmcb->ss.sel   = regs->ss;
    vmcb->rsp      = regs->rsp;   
    vmcb->rflags   = regs->rflags;
    vmcb->cs.sel   = regs->cs;
    vmcb->rip      = regs->rip;
    if (regs->rflags & EF_TF)
        *intercepts |= EXCEPTION_BITMAP_DB;
    else
        *intercepts &= ~EXCEPTION_BITMAP_DB;
}
#endif /* !(__i386__) */

int svm_paging_enabled(struct vcpu *v)
{
    unsigned long cr0;

    cr0 = v->arch.hvm_svm.cpu_shadow_cr0;

    return (cr0 & X86_CR0_PE) && (cr0 & X86_CR0_PG);
}


/* Make sure that xen intercepts any FP accesses from current */
void svm_stts(struct vcpu *v) 
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    /* FPU state already dirty? Then no need to setup_fpu() lazily. */
    if ( test_bit(_VCPUF_fpu_dirtied, &v->vcpu_flags) )
        return;

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
    reset_stack_and_jump(svm_asm_do_launch);
}

static void svm_freeze_time(struct vcpu *v)
{
    struct hvm_time_info *time_info = &v->domain->arch.hvm_domain.vpit.time_info;
    
    if ( time_info->first_injected && !v->domain->arch.hvm_domain.guest_time ) {
        v->domain->arch.hvm_domain.guest_time = svm_get_guest_time(v);
        time_info->count_advance += (NOW() - time_info->count_point);
        stop_timer(&(time_info->pit_timer));
    }
}

static void svm_ctxt_switch_from(struct vcpu *v)
{
    svm_freeze_time(v);
}

static void svm_ctxt_switch_to(struct vcpu *v)
{
}

void svm_final_setup_guest(struct vcpu *v)
{
    v->arch.schedule_tail    = arch_svm_do_launch;
    v->arch.ctxt_switch_from = svm_ctxt_switch_from;
    v->arch.ctxt_switch_to   = svm_ctxt_switch_to;

    if (v == v->domain->vcpu[0]) 
    {
	struct domain *d = v->domain;
	struct vcpu *vc;

	/* Initialize monitor page table */
	for_each_vcpu(d, vc)
	    vc->arch.monitor_table = mk_pagetable(0);

        /* 
         * Required to do this once per domain
         * TODO: add a seperate function to do these.
         */
        memset(&d->shared_info->evtchn_mask[0], 0xff, 
               sizeof(d->shared_info->evtchn_mask));       

        /* 
         * Put the domain in shadow mode even though we're going to be using
         * the shared 1:1 page table initially. It shouldn't hurt 
         */
        shadow_mode_enable(d, 
                SHM_enable|SHM_refcounts|
		SHM_translate|SHM_external|SHM_wr_pt_pte);
    }
}


static void svm_relinquish_guest_resources(struct domain *d)
{
    extern void destroy_vmcb(struct arch_svm_struct *); /* XXX */
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            continue;
#if 0
        /* Memory leak by not freeing this. XXXKAF: *Why* is not per core?? */
        free_host_save_area(v->arch.hvm_svm.host_save_area);
#endif

        destroy_vmcb(&v->arch.hvm_svm);
        free_monitor_pagetable(v);
        kill_timer(&v->arch.hvm_svm.hlt_timer);
        if ( hvm_apic_support(v->domain) && (VLAPIC(v) != NULL) ) 
        {
            kill_timer( &(VLAPIC(v)->vlapic_timer) );
            xfree(VLAPIC(v));
        }
    }

    kill_timer(&d->arch.hvm_domain.vpit.time_info.pit_timer);

    if ( d->arch.hvm_domain.shared_page_va )
        unmap_domain_page_global(
            (void *)d->arch.hvm_domain.shared_page_va);

    shadow_direct_map_clean(d);
}


void arch_svm_do_resume(struct vcpu *v) 
{
    /* pinning VCPU to a different core? */
    if ( v->arch.hvm_svm.launch_core == smp_processor_id()) {
        svm_do_resume( v );
        reset_stack_and_jump( svm_asm_do_resume );
    }
    else {
        printk("VCPU core pinned: %d to %d\n", 
                v->arch.hvm_svm.launch_core, smp_processor_id() );
        v->arch.hvm_svm.launch_core = smp_processor_id();
        svm_migrate_timers( v );
        svm_do_resume( v );
        reset_stack_and_jump( svm_asm_do_resume );
    }
}


void svm_migrate_timers(struct vcpu *v)
{
    struct hvm_time_info *time_info = &v->domain->arch.hvm_domain.vpit.time_info;

    migrate_timer(&time_info->pit_timer, v->processor);
    migrate_timer(&v->arch.hvm_svm.hlt_timer, v->processor);
    if ( hvm_apic_support(v->domain) && VLAPIC( v ))
        migrate_timer( &(VLAPIC(v)->vlapic_timer ), v->processor );
}


static int svm_do_page_fault(unsigned long va, struct cpu_user_regs *regs) 
{
    struct vcpu *v = current;
    unsigned long eip;
    unsigned long gpa; /* FIXME: PAE */
    int result;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);

//#if HVM_DEBUG
    eip = vmcb->rip;
    HVM_DBG_LOG(DBG_LEVEL_VMMU, 
            "svm_do_page_fault = 0x%lx, eip = %lx, error_code = %lx",
            va, eip, (unsigned long)regs->error_code);
//#endif

    if ( !svm_paging_enabled(v) )
    {
        if ( shadow_direct_map_fault(va, regs) ) 
            return 1;

        handle_mmio(va, va);
        TRACE_VMEXIT(2,2);
        return 1;
    }


    gpa = gva_to_gpa(va);

    /* Use 1:1 page table to identify MMIO address space */
    if (mmio_space(gpa))
    {
	/* No support for APIC */
        if (!hvm_apic_support(v->domain) && gpa >= 0xFEC00000)
        { 
            int inst_len;
            inst_len = svm_instruction_length(v);
            if (inst_len == -1)
            {
                printf("%s: INST_LEN - Unable to decode properly.\n", __func__);
                domain_crash_synchronous();
            }

            __update_guest_eip(vmcb, inst_len);

            return 1;
        }

        TRACE_VMEXIT (2,2);
        handle_mmio(va, gpa);

        return 1;
    }
    
    result = shadow_fault(va, regs);

    if( result ) {
        /* Let's make sure that the Guest TLB is flushed */
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    }

    TRACE_VMEXIT (2,result);

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
    svm_inject_exception(vmcb, TRAP_gp_fault, 1, error_code);
}

/* Reserved bits: [31:14], [12:1] */
#define SVM_VCPU_CPUID_L1_RESERVED 0xffffdffe

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

    cpuid(input, &eax, &ebx, &ecx, &edx);

    if (input == 1)
    {
        if ( !hvm_apic_support(v->domain) ||
                !vlapic_global_enabled((VLAPIC(v))) )
        {
            clear_bit(X86_FEATURE_APIC, &edx);
            /* Since the apic is disabled, avoid any confusion about SMP cpus being available */
            clear_bit(X86_FEATURE_HT, &edx);  /* clear the hyperthread bit */
            ebx &= 0xFF00FFFF;  /* set the logical processor count to 1 */
            ebx |= 0x00010000;
        }
	    
#if CONFIG_PAGING_LEVELS < 3
        clear_bit(X86_FEATURE_NX, &edx);
        clear_bit(X86_FEATURE_PAE, &edx);
        clear_bit(X86_FEATURE_PSE, &edx);
        clear_bit(X86_FEATURE_PSE36, &edx);
#else
        if ( v->domain->arch.ops->guest_paging_levels == PAGING_L2 )
        {
            if ( !v->domain->arch.hvm_domain.pae_enabled )
            {
               clear_bit(X86_FEATURE_PAE, &edx);
               clear_bit(X86_FEATURE_NX, &edx);
            }
            clear_bit(X86_FEATURE_PSE, &edx);
            clear_bit(X86_FEATURE_PSE36, &edx);
        }
#endif	
        /* Clear out reserved bits. */
        ecx &= ~SVM_VCPU_CPUID_L1_RESERVED; /* mask off reserved bits */
        clear_bit(X86_FEATURE_MWAIT & 31, &ecx);
    }
#ifdef __i386__
    else if ( input == 0x80000001 )
    {
        /* Mask feature for Intel ia32e or AMD long mode. */
        clear_bit(X86_FEATURE_LM & 31, &edx);
    }
#endif

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
#if __x86_64__
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
                           

static void svm_dr_access (struct vcpu *v, unsigned int reg, unsigned int type,
        struct cpu_user_regs *regs)
{
    unsigned long *reg_p = 0;
    unsigned int gpreg = 0;
    unsigned long eip;
    int inst_len; 
    int index;
    struct vmcb_struct *vmcb;
    u8 buffer[MAX_INST_LEN];
    u8 prefix = 0;

    vmcb = v->arch.hvm_svm.vmcb;
    
    ASSERT(vmcb);

    eip = vmcb->rip;
    inst_copy_from_guest(buffer, svm_rip2pointer(vmcb), sizeof(buffer));
    index = skip_prefix_bytes(buffer, sizeof(buffer));
    
    ASSERT(buffer[index+0] == 0x0f && (buffer[index+1] & 0xFD) == 0x21);

    if (index > 0 && (buffer[index-1] & 0xF0) == 0x40)
        prefix = buffer[index-1];

    gpreg = decode_src_reg(prefix, buffer[index + 2]);
    ASSERT(reg == decode_dest_reg(prefix, buffer[index + 2]));

    HVM_DBG_LOG(DBG_LEVEL_1, "svm_dr_access : eip=%lx, reg=%d, gpreg = %x",
            eip, reg, gpreg);

    reg_p = get_reg_p(gpreg, regs, vmcb);
        
    switch (type) 
    {
    case TYPE_MOV_TO_DR: 
        inst_len = __get_instruction_length(vmcb, INSTR_MOV2DR, buffer);
        v->arch.guest_context.debugreg[reg] = *reg_p; 
        break;
    case TYPE_MOV_FROM_DR:
        inst_len = __get_instruction_length(vmcb, INSTR_MOVDR2, buffer);
        *reg_p = v->arch.guest_context.debugreg[reg];
        break;
    default:
        __hvm_bug(regs);
        break;
    }
    ASSERT(inst_len > 0);
    __update_guest_eip(vmcb, inst_len);
}


static unsigned int check_for_null_selector(struct vmcb_struct *vmcb, 
        unsigned int dir, unsigned long *base, unsigned int real)

{
    unsigned char inst[MAX_INST_LEN];
    segment_selector_t seg;
    int i;

    memset(inst, 0, MAX_INST_LEN);
    if (inst_copy_from_guest(inst, svm_rip2pointer(vmcb), sizeof(inst)) 
            != MAX_INST_LEN) 
    {
        printk("check_for_null_selector: get guest instruction failed\n");
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
        case 0x67: /* addr32 */
#if __x86_64__
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
        case 0x2e: /* CS */
            seg = vmcb->cs;
            break;
        case 0x36: /* SS */
            seg = vmcb->ss;
            break;
        case 0x26: /* ES */
            seg = vmcb->es;
            break;
        case 0x64: /* FS */
            seg = vmcb->fs;
            break;
        case 0x65: /* GS */
            seg = vmcb->gs;
            break;
        case 0x3e: /* DS */
            /* FALLTHROUGH */
            seg = vmcb->ds;
            break;
        default:
            if (dir == IOREQ_READ) /* IN/INS instruction? */
                seg = vmcb->es;
            else
                seg = vmcb->ds;
        }
        
        if (base)
            *base = seg.base;

        return seg.attributes.fields.p;
    }

    ASSERT(0);
    return 0;
}


/* Get the address of INS/OUTS instruction */
static inline unsigned long svm_get_io_address(struct vmcb_struct *vmcb, 
        struct cpu_user_regs *regs, unsigned int dir, unsigned int real)
{
    unsigned long addr = 0;
    unsigned long base = 0;

    check_for_null_selector(vmcb, dir, &base, real);

    if (dir == IOREQ_WRITE)
    {
        if (real)
            addr = (regs->esi & 0xFFFF) + base;
        else
            addr = regs->esi + base;
    }
    else
    {
        if (real)
            addr = (regs->edi & 0xFFFF) + base;
        else
            addr = regs->edi + base;
    }

    return addr;
}


static void svm_io_instruction(struct vcpu *v, struct cpu_user_regs *regs) 
{
    struct mmio_op *mmio_opp;
    unsigned long eip, cs, eflags, cr0;
    unsigned long port;
    unsigned int real, size, dir;
    ioio_info_t info;

    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(vmcb);
    mmio_opp = &current->arch.hvm_vcpu.mmio_op;
    mmio_opp->instr = INSTR_PIO;
    mmio_opp->flags = 0;

    eip = vmcb->rip;
    cs =  vmcb->cs.sel;
    eflags = vmcb->rflags;

    info.bytes = vmcb->exitinfo1;

    port = info.fields.port; /* port used to be addr */
    dir = info.fields.type; /* direction */ 
    if (info.fields.sz32) 
        size = 4;
    else if (info.fields.sz16)
        size = 2;
    else 
        size = 1;

    cr0 = vmcb->cr0;
    real = (eflags & X86_EFLAGS_VM) || !(cr0 & X86_CR0_PE);

    HVM_DBG_LOG(DBG_LEVEL_IO, 
                "svm_io_instruction: port 0x%lx real %d, eip=%lx:%lx, "
                "exit_qualification = %lx",
                (unsigned long) port, real, cs, eip, (unsigned long)info.bytes);
    /* string instruction */
    if (info.fields.str)
    { 
        unsigned long addr, count = 1;
        int sign = regs->eflags & EF_DF ? -1 : 1;

        /* Need the original rip, here. */
        addr = svm_get_io_address(vmcb, regs, dir, real);

        /* "rep" prefix */
        if (info.fields.rep) 
        {
            mmio_opp->flags |= REPZ;
            count = real ? regs->ecx & 0xFFFF : regs->ecx;
        }

        /*
         * Handle string pio instructions that cross pages or that
         * are unaligned. See the comments in hvm_platform.c/handle_mmio()
         */
        if ((addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK))
        {
            unsigned long value = 0;

            mmio_opp->flags |= OVERLAP;

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
                vmcb->rip = vmcb->exitinfo2;

            send_pio_req(regs, port, count, size, addr, dir, 1);
        }
    } 
    else 
    {
        /* 
         * On SVM, the RIP of the intruction following the IN/OUT is saved in
         * ExitInfo2
         */
        vmcb->rip = vmcb->exitinfo2;

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
            svm_inject_exception(vmcb, TRAP_gp_fault, 1, 0);
        }

        if (test_bit(SVM_CPU_STATE_LME_ENABLED, &v->arch.hvm_svm.cpu_state))
        {
            /* Here the PAE is should to be opened */
            HVM_DBG_LOG(DBG_LEVEL_1, "Enable the Long mode\n");
            set_bit(SVM_CPU_STATE_LMA_ENABLED,
                    &v->arch.hvm_svm.cpu_state);
            vmcb->efer |= (EFER_LMA | EFER_LME);
            if (!shadow_set_guest_paging_levels(v->domain, PAGING_L4) )
            {
                printk("Unsupported guest paging levels\n");
                domain_crash_synchronous(); /* need to take a clean path */
            }
        }
        else
#endif  /* __x86_64__ */
        {
#if CONFIG_PAGING_LEVELS >= 3
            /* seems it's a 32-bit or 32-bit PAE guest */
            if ( test_bit(SVM_CPU_STATE_PAE_ENABLED,
                        &v->arch.hvm_svm.cpu_state) )
            {
                /* The guest enables PAE first and then it enables PG, it is
                 * really a PAE guest */
                if ( !shadow_set_guest_paging_levels(v->domain, PAGING_L3) )
                {
                    printk("Unsupported guest paging levels\n");
                    domain_crash_synchronous();
                }
            }
            else
            {
                if ( !shadow_set_guest_paging_levels(v->domain, PAGING_L2) )
                {
                    printk("Unsupported guest paging levels\n");
                    domain_crash_synchronous(); /* need to take a clean path */
                }
            }
#endif
        }

        /* Now arch.guest_table points to machine physical. */
        v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);
        update_pagetables(v);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx", 
                (unsigned long) (mfn << PAGE_SHIFT));

        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
        vmcb->cr3 = pagetable_get_paddr(v->arch.shadow_table);

        /* arch->shadow_table should hold the next CR3 for shadow */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx\n", 
                    v->arch.hvm_svm.cpu_cr3, mfn);

        return 1;
    }

    if ( !((value & X86_CR0_PE) && (value & X86_CR0_PG)) && paging_enabled )
        if ( v->arch.hvm_svm.cpu_cr3 ) {
            put_page(mfn_to_page(get_mfn_from_gpfn(
                      v->arch.hvm_svm.cpu_cr3 >> PAGE_SHIFT)));
            v->arch.guest_table = mk_pagetable(0);
        }

    /*
     * SVM implements paged real-mode and when we return to real-mode
     * we revert back to the physical mappings that the domain builder
     * created.
     */
    if ((value & X86_CR0_PE) == 0) {
    	if (value & X86_CR0_PG) {
            svm_inject_exception(vmcb, TRAP_gp_fault, 1, 0);
            return 0;
        }

        clear_all_shadow_status( v->domain );
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
        vmcb->cr3 = pagetable_get_paddr(v->domain->arch.phys_table);
    }
    else if ( (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PE )
    {
        /* we should take care of this kind of situation */
        clear_all_shadow_status(v->domain);
        set_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
        vmcb->cr3 = pagetable_get_paddr(v->domain->arch.phys_table);
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
#if 0
        value = vmcb->m_cr8;
#else
        ASSERT(0);
#endif
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
            shadow_sync_all(v->domain);
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
            v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);

            if (old_base_mfn)
                put_page(mfn_to_page(old_base_mfn));

            /*
             * arch.shadow_table should now hold the next CR3 for shadow
             */
#if CONFIG_PAGING_LEVELS >= 3
            if ( v->domain->arch.ops->guest_paging_levels == PAGING_L3 )
                shadow_sync_all(v->domain);
#endif
            v->arch.hvm_svm.cpu_cr3 = value;
            update_pagetables(v);
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx", value);
            vmcb->cr3 = pagetable_get_paddr(v->arch.shadow_table);
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
#if CONFIG_PAGING_LEVELS >= 4
                unsigned long mfn, old_base_mfn;

                if( !shadow_set_guest_paging_levels(v->domain, PAGING_L3) )
                {
                    printk("Unsupported guest paging levels\n");
                    domain_crash_synchronous(); /* need to take a clean path */
                }

                if ( !VALID_MFN(mfn = get_mfn_from_gpfn(
                                    v->arch.hvm_svm.cpu_cr3 >> PAGE_SHIFT)) ||
                     !get_page(mfn_to_page(mfn), v->domain) )
                {
                    printk("Invalid CR3 value = %lx", v->arch.hvm_svm.cpu_cr3);
                    domain_crash_synchronous(); /* need to take a clean path */
                }

                old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
                if ( old_base_mfn )
                    put_page(mfn_to_page(old_base_mfn));

                /*
                 * Now arch.guest_table points to machine physical.
                 */

                v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);
                update_pagetables(v);

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                            (unsigned long) (mfn << PAGE_SHIFT));

                vmcb->cr3 = pagetable_get_paddr(v->arch.shadow_table);

                /*
                 * arch->shadow_table should hold the next CR3 for shadow
                 */

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                            v->arch.hvm_svm.cpu_cr3, mfn);
#endif
            }
            else
            {
                /*  The guest is a 64 bit or 32-bit PAE guest. */
#if CONFIG_PAGING_LEVELS >= 4
                if ( (v->domain->arch.ops != NULL) &&
                        v->domain->arch.ops->guest_paging_levels == PAGING_L2)
                {
                    /* Seems the guest first enables PAE without enabling PG,
                     * it must enable PG after that, and it is a 32-bit PAE
                     * guest */

                    if ( !shadow_set_guest_paging_levels(v->domain, PAGING_L3) )
                    {
                        printk("Unsupported guest paging levels\n");
                        domain_crash_synchronous();
                    }                   
                }
                else
                {
                    if ( !shadow_set_guest_paging_levels(v->domain,
                                                            PAGING_L4) )
                    {
                        printk("Unsupported guest paging levels\n");
                        domain_crash_synchronous();
                    }
                }
#endif
            }
        }
        else if (value & X86_CR4_PAE) {
            set_bit(SVM_CPU_STATE_PAE_ENABLED, &v->arch.hvm_svm.cpu_state);
        } else {
            if (test_bit(SVM_CPU_STATE_LMA_ENABLED,
                         &v->arch.hvm_svm.cpu_state)) {
                svm_inject_exception(vmcb, TRAP_gp_fault, 1, 0);
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
            shadow_sync_all(v->domain);
        }
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
    /* get index to first actual instruction byte - as we will need to know where the 
     * prefix lives later on
     */
    index = skip_prefix_bytes(buffer, sizeof(buffer));
    
    if (type == TYPE_MOV_TO_CR) 
    {
        inst_len = __get_instruction_length_from_list(vmcb, list_a, 
                ARR_SIZE(list_a), &buffer[index], &match);
    }
    else
    {
        inst_len = __get_instruction_length_from_list(vmcb, list_b, 
                ARR_SIZE(list_b), &buffer[index], &match);
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

static inline void svm_do_msr_access(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int  inst_len;
    u64 msr_content=0;

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
        {
            struct hvm_time_info *time_info;

            rdtscll(msr_content);
            time_info = &v->domain->arch.hvm_domain.vpit.time_info;
            msr_content += time_info->cache_tsc_offset;
            break;
        }
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
            svm_set_guest_time(v, msr_content);
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
            long_mode_do_msr_write(regs);
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


/*
 * Need to use this exit to reschedule
 */
static inline void svm_vmexit_do_hlt(struct vmcb_struct *vmcb)
{
    struct vcpu *v = current;
    struct hvm_virpit *vpit = &v->domain->arch.hvm_domain.vpit;
    s_time_t  next_pit = -1, next_wakeup;

    __update_guest_eip(vmcb, 1);

    /* check for interrupt not handled or new interrupt */
    if ( vmcb->vintr.fields.irq || cpu_has_pending_irq(v) )
       return; 

    if ( !v->vcpu_id )
        next_pit = get_pit_scheduled(v, vpit);
    next_wakeup = get_apictime_scheduled(v);
    if ( (next_pit != -1 && next_pit < next_wakeup) || next_wakeup == -1 )
        next_wakeup = next_pit;
    if ( next_wakeup != - 1 )
        set_timer(&current->arch.hvm_svm.hlt_timer, next_wakeup);
    hvm_safe_block();
}


static inline void svm_vmexit_do_mwait(void)
{
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
    u8 opcode[MAX_INST_SIZE], prefix, length = MAX_INST_SIZE;
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
        printk("svm_handle_invlpg (): Error reading memory %d bytes\n", length);
       __hvm_bug(regs);
    }

    if (invlpga)
    {
        inst_len = __get_instruction_length(vmcb, INSTR_INVLPGA, opcode);
        ASSERT(inst_len > 0);
        __update_guest_eip(vmcb, inst_len);

        /* 
         * The address is implicit on this instruction At the moment, we don't
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

    /* VMMCALL sanity check */
    if (vmcb->cpl > get_vmmcall_cpl(regs->edi))
    {
        printf("VMMCALL CPL check failed\n");
        return -1;
    }

    /* handle the request */
    switch (regs->edi) 
    {
    case VMMCALL_RESET_TO_REALMODE:
        if (svm_do_vmmcall_reset_to_realmode(v, regs)) 
        {
            printf("svm_do_vmmcall_reset_to_realmode() failed\n");
            return -1;
        }
    
        /* since we just reset the VMCB, return without adjusting the eip */
        return 0;
    case VMMCALL_DEBUG:
        printf("DEBUG features not implemented yet\n");
        break;
    default:
    break;
    }

    hvm_print_line(v, regs->eax); /* provides the current domain */

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

    gpa = gva_to_gpa( gva );
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

    // This is actually overkill - we only need to make sure the hl2 is in-sync.
    shadow_sync_va(v, gva);

    gpte.l1 = 0;
    __copy_from_user(&gpte, &linear_pg_table[ l1_linear_offset(gva) ], sizeof(gpte) );
    printk( "G-PTE = %x, flags=%x\n", gpte.l1, l1e_get_flags(gpte) );
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
    v->arch.hvm_svm.injecting_event = 0;

    vmcb->tlb_control = 1;

#ifdef SVM_EXTRA_DEBUG
{
#if defined(__i386__)
#define	rip	eip
#endif

    static unsigned long intercepts_counter = 0;

    if (svm_dbg_on && exit_reason == VMEXIT_EXCEPTION_PF) 
    {
        if (svm_paging_enabled(v) && !mmio_space(gva_to_gpa(vmcb->exitinfo2)))
        {
            printk("I%08ld,ExC=%s(%d),IP=%x:%llx,I1=%llx,I2=%llx,INT=%llx, gpa=%llx\n", 
                    intercepts_counter,
                    exit_reasons[exit_reason], exit_reason, regs.cs,
		    (unsigned long long) regs.rip,
		    (unsigned long long) vmcb->exitinfo1,
		    (unsigned long long) vmcb->exitinfo2,
		    (unsigned long long) vmcb->exitintinfo.bytes,
            (unsigned long long) gva_to_gpa( vmcb->exitinfo2 ) );
        }
        else 
        {
            printk("I%08ld,ExC=%s(%d),IP=%x:%llx,I1=%llx,I2=%llx,INT=%llx\n", 
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
            printk("I%08ld,ExC=%s(%d),IP=%x:%llx,I1=%llx,I2=%llx,INT=%llx\n", 
                    intercepts_counter,
                    exit_reasons[exit_reason], exit_reason, regs.cs,
		    (unsigned long long) regs.rip,
		    (unsigned long long) vmcb->exitinfo1,
		    (unsigned long long) vmcb->exitinfo2,
		    (unsigned long long) vmcb->exitintinfo.bytes);
        } 
        else 
        {
            printk("I%08ld,ExC=%d(0x%x),IP=%x:%llx,I1=%llx,I2=%llx,INT=%llx\n", 
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
       if (svm_paging_enabled(v) && !mmio_space(gva_to_gpa(vmcb->exitinfo2)))     
           walk_shadow_and_guest_pt( vmcb->exitinfo2 );
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
#undef	rip
#endif

}
#endif /* SVM_EXTRA_DEBUG */

    if (exit_reason == -1)
    {
        printk("%s: exit_reason == -1 - Did someone clobber the VMCB\n", 
                __func__);
        BUG();
        domain_crash_synchronous();
    }

    perfc_incra(vmexits, exit_reason);
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
            svm_inject_exception(vmcb, TRAP_int3, 0, 0);
#endif
        break;

    case VMEXIT_EXCEPTION_NM:
        svm_do_no_device_fault(vmcb);
        break;  

    case VMEXIT_EXCEPTION_GP:
        /* This should probably not be trapped in the future */
        regs.error_code = vmcb->exitinfo1;
        v->arch.hvm_svm.injecting_event = 1;
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

        v->arch.hvm_vcpu.mmio_op.inst_decoder_regs = &regs;

//printk("PF1\n");
        if (!(error = svm_do_page_fault(va, &regs))) 
        {
            v->arch.hvm_svm.injecting_event = 1;
            /* Inject #PG using Interruption-Information Fields */
            svm_inject_exception(vmcb, TRAP_page_fault, 1, regs.error_code);

            v->arch.hvm_svm.cpu_cr2 = va;
            vmcb->cr2 = va;
            TRACE_3D(TRC_VMX_INT, v->domain->domain_id, 
                    VMEXIT_EXCEPTION_PF, va);
        }
        break;
    }

    case VMEXIT_EXCEPTION_DF:
        printk("Guest double fault");
        BUG();
        break;

    case VMEXIT_INTR:
        raise_softirq(SCHEDULE_SOFTIRQ);
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

    case VMEXIT_DR0_READ:
        svm_dr_access(v, 0, TYPE_MOV_FROM_DR, &regs);
        break;

    case VMEXIT_DR1_READ:
        svm_dr_access(v, 1, TYPE_MOV_FROM_DR, &regs);
        break;

    case VMEXIT_DR2_READ:
        svm_dr_access(v, 2, TYPE_MOV_FROM_DR, &regs);
        break;

    case VMEXIT_DR3_READ:
        svm_dr_access(v, 3, TYPE_MOV_FROM_DR, &regs);
        break;

    case VMEXIT_DR6_READ:
        svm_dr_access(v, 6, TYPE_MOV_FROM_DR, &regs);
        break;

    case VMEXIT_DR7_READ:
        svm_dr_access(v, 7, TYPE_MOV_FROM_DR, &regs);
        break;

    case VMEXIT_DR0_WRITE:
        svm_dr_access(v, 0, TYPE_MOV_TO_DR, &regs);
        break;

    case VMEXIT_DR1_WRITE:
        svm_dr_access(v, 1, TYPE_MOV_TO_DR, &regs);
        break;

    case VMEXIT_DR2_WRITE:
        svm_dr_access(v, 2, TYPE_MOV_TO_DR, &regs);
        break;

    case VMEXIT_DR3_WRITE:
        svm_dr_access(v, 3, TYPE_MOV_TO_DR, &regs);
        break;

    case VMEXIT_DR6_WRITE:
        svm_dr_access(v, 6, TYPE_MOV_TO_DR, &regs);
        break;

    case VMEXIT_DR7_WRITE:
        svm_dr_access(v, 7, TYPE_MOV_TO_DR, &regs);
        break;

    case VMEXIT_IOIO:
        svm_io_instruction(v, &regs);
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
#ifdef __i386__
    asm volatile("movl %0,%%cr2": :"r" (v->arch.hvm_svm.cpu_cr2));
#else
    asm volatile("movq %0,%%cr2": :"r" (v->arch.hvm_svm.cpu_cr2));
#endif
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
        if ( !asidpool_assign_next( vmcb, 1,
	     v->arch.hvm_svm.asid_core, v->arch.hvm_svm.launch_core )) {
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
