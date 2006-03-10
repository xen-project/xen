#include <linux/config.h>
#include <linux/module.h>

#include <linux/jiffies.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/kernel_stat.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/random.h>	/* for rand_initialize_irq() */
#include <linux/signal.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/threads.h>
#include <linux/bitops.h>

#include <asm/delay.h>
#include <asm/intrinsics.h>
#include <asm/io.h>
#include <asm/hw_irq.h>
#include <asm/machvec.h>
#include <asm/pgtable.h>
#include <asm/system.h>

#include <asm/vcpu.h>
#include <xen/irq.h>
#ifdef CONFIG_SMP
#   define IS_RESCHEDULE(vec)   (vec == IA64_IPI_RESCHEDULE)
#else
#   define IS_RESCHEDULE(vec)   (0)
#endif

#ifdef CONFIG_PERFMON
# include <asm/perfmon.h>
#endif

#define IRQ_DEBUG	0

#define vmx_irq_enter()		\
	add_preempt_count(HARDIRQ_OFFSET);

/* Now softirq will be checked when leaving hypervisor, or else
 * scheduler irq will be executed too early.
 */
#define vmx_irq_exit(void)	\
	sub_preempt_count(HARDIRQ_OFFSET);
/*
 * That's where the IVT branches when we get an external
 * interrupt. This branches to the correct hardware IRQ handler via
 * function ptr.
 */
void
vmx_ia64_handle_irq (ia64_vector vector, struct pt_regs *regs)
{
	unsigned long saved_tpr;
	int	wake_dom0 = 0;


#if IRQ_DEBUG
	{
		unsigned long bsp, sp;

		/*
		 * Note: if the interrupt happened while executing in
		 * the context switch routine (ia64_switch_to), we may
		 * get a spurious stack overflow here.  This is
		 * because the register and the memory stack are not
		 * switched atomically.
		 */
		bsp = ia64_getreg(_IA64_REG_AR_BSP);
		sp = ia64_getreg(_IA64_REG_AR_SP);

		if ((sp - bsp) < 1024) {
			static unsigned char count;
			static long last_time;

			if (jiffies - last_time > 5*HZ)
				count = 0;
			if (++count < 5) {
				last_time = jiffies;
				printk("ia64_handle_irq: DANGER: less than "
				       "1KB of free stack space!!\n"
				       "(bsp=0x%lx, sp=%lx)\n", bsp, sp);
			}
		}
	}
#endif /* IRQ_DEBUG */

	/*
	 * Always set TPR to limit maximum interrupt nesting depth to
	 * 16 (without this, it would be ~240, which could easily lead
	 * to kernel stack overflows).
	 */
	vmx_irq_enter();
	saved_tpr = ia64_getreg(_IA64_REG_CR_TPR);
	ia64_srlz_d();
	while (vector != IA64_SPURIOUS_INT_VECTOR) {
	    if (!IS_RESCHEDULE(vector)) {
		ia64_setreg(_IA64_REG_CR_TPR, vector);
		ia64_srlz_d();

		if (vector != IA64_TIMER_VECTOR) {
			/* FIXME: Leave IRQ re-route later */
			if (!VMX_DOMAIN(dom0->vcpu[0]))
				vcpu_pend_interrupt(dom0->vcpu[0],vector);
			else
				vmx_vcpu_pend_interrupt(dom0->vcpu[0],vector);
			wake_dom0 = 1;
		}
		else {	// FIXME: Handle Timer only now
			__do_IRQ(local_vector_to_irq(vector), regs);
		}
		
		/*
		 * Disable interrupts and send EOI:
		 */
		local_irq_disable();
		ia64_setreg(_IA64_REG_CR_TPR, saved_tpr);
	    }
	    ia64_eoi();
	    vector = ia64_get_ivr();
	}
	/*
	 * This must be done *after* the ia64_eoi().  For example, the keyboard softirq
	 * handler needs to be able to wait for further keyboard interrupts, which can't
	 * come through until ia64_eoi() has been done.
	 */
	vmx_irq_exit();
	if (wake_dom0 && current->domain != dom0 ) 
		vcpu_wake(dom0->vcpu[0]);
}
