/*
 *  linux/arch/i386/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>		/* For unblank_screen() */

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/hardirq.h>

extern void die(const char *,struct pt_regs *,long);

pgd_t *cur_pgd;

extern spinlock_t timerlist_lock;

/*
 * Unlock any spinlocks which will prevent us from getting the
 * message out (timerlist_lock is acquired through the
 * console unblank code)
 */
void bust_spinlocks(int yes)
{
	spin_lock_init(&timerlist_lock);
	if (yes) {
		oops_in_progress = 1;
	} else {
		int loglevel_save = console_loglevel;
#ifdef CONFIG_VT
		unblank_screen();
#endif
		oops_in_progress = 0;
		/*
		 * OK, the message is on the console.  Now we call printk()
		 * without oops_in_progress set so that printk will give klogd
		 * a poke.  Hold onto your hats...
		 */
		console_loglevel = 15;		/* NMI oopser may have shut the console up */
		printk(" ");
		console_loglevel = loglevel_save;
	}
}

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 */
asmlinkage void do_page_fault(struct pt_regs *regs, 
                              unsigned long error_code,
                              unsigned long address)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm;
	struct vm_area_struct * vma;
	unsigned long page;
	unsigned long fixup;
	int write;
	siginfo_t info;

        /* Set the "privileged fault" bit to something sane. */
        error_code &= 3;
        error_code |= (regs->xcs & 2) << 1;

#if MMU_UPDATE_DEBUG > 0
        if ( (error_code == 0) && (address >= TASK_SIZE) )
        {
            unsigned long paddr = __pa(address);
            int i;
            for ( i = 0; i < mmu_update_queue_idx; i++ )
            {
                if ( update_debug_queue[i].ptr == paddr )
                {
                    printk("XXX now(EIP=%08lx:ptr=%08lx) "
                           "then(%s/%d:p/v=%08lx/%08lx)\n",
                           regs->eip, address,
                           update_debug_queue[i].file,
                           update_debug_queue[i].line,
                           update_debug_queue[i].ptr,
                           update_debug_queue[i].val);
                }
            }
        }
#endif

	if ( flush_page_update_queue() != 0 )
		return;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 1) == 0.
	 */
	if (address >= TASK_SIZE && !(error_code & 5))
		goto vmalloc_fault;

	mm = tsk->mm;
	info.si_code = SEGV_MAPERR;

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (in_interrupt() || !mm)
		goto no_context;

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (error_code & 4) {
		/*
		 * accessing the stack below %esp is always a bug.
		 * The "+ 32" is there due to some instructions (like
		 * pusha) doing post-decrement on the stack and that
		 * doesn't show up until later..
		 */
		if (address + 32 < regs->esp)
			goto bad_area;
	}
	if (expand_stack(vma, address))
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
good_area:
	info.si_code = SEGV_ACCERR;
	write = 0;
	switch (error_code & 3) {
		default:	/* 3: write, present */
			/* fall through */
		case 2:		/* write, not present */
			if (!(vma->vm_flags & VM_WRITE))
				goto bad_area;
			write++;
			break;
		case 1:		/* read, present */
			goto bad_area;
		case 0:		/* read, not present */
			if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
				goto bad_area;
	}

 survive:
	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	switch (handle_mm_fault(mm, vma, address, write)) {
	case 1:
		tsk->min_flt++;
		break;
	case 2:
		tsk->maj_flt++;
		break;
	case 0:
		goto do_sigbus;
	default:
		goto out_of_memory;
	}

	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
bad_area:
	up_read(&mm->mmap_sem);

	/* User mode accesses just cause a SIGSEGV */
	if (error_code & 4) {
		tsk->thread.cr2 = address;
		/* Kernel addresses are always protection faults */
		tsk->thread.error_code = error_code | (address >= TASK_SIZE);
		tsk->thread.trap_no = 14;
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		/* info.si_code has been set above */
		info.si_addr = (void *)address;
		force_sig_info(SIGSEGV, &info, tsk);
		return;
	}

no_context:
	/* Are we prepared to handle this kernel fault?  */
	if ((fixup = search_exception_table(regs->eip)) != 0) {
		regs->eip = fixup;
		return;
	}

/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */

	bust_spinlocks(1);

	if (address < PAGE_SIZE)
		printk(KERN_ALERT "Unable to handle kernel NULL pointer dereference");
	else
		printk(KERN_ALERT "Unable to handle kernel paging request");
	printk(" at virtual address %08lx\n",address);
	printk(" printing eip:\n");
	printk("%08lx\n", regs->eip);
        page = ((unsigned long *) cur_pgd)[address >> 22];
        printk(KERN_ALERT "*pde=%08lx(%08lx)\n", page, machine_to_phys(page));
	if (page & 1) {
		page &= PAGE_MASK;
		address &= 0x003ff000;
                page = machine_to_phys(page);
		page = ((unsigned long *) __va(page))[address >> PAGE_SHIFT];
                printk(KERN_ALERT "*pte=%08lx(%08lx)\n", page, 
                       machine_to_phys(page));
	}
	die("Oops", regs, error_code);
	bust_spinlocks(0);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	if (tsk->pid == 1) {
		yield();
		goto survive;
	}
	up_read(&mm->mmap_sem);
	printk("VM: killing process %s\n", tsk->comm);
	if (error_code & 4)
		do_exit(SIGKILL);
	goto no_context;

do_sigbus:
	up_read(&mm->mmap_sem);

	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	tsk->thread.cr2 = address;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 14;
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = BUS_ADRERR;
	info.si_addr = (void *)address;
	force_sig_info(SIGBUS, &info, tsk);

	/* Kernel mode? Handle exceptions or die */
	if (!(error_code & 4))
		goto no_context;
	return;

vmalloc_fault:
	{
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk" here. We might be inside
		 * an interrupt in the middle of a task switch..
		 */
		int offset = __pgd_offset(address);
		pgd_t *pgd, *pgd_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		pgd = offset + cur_pgd;
		pgd_k = init_mm.pgd + offset;

		if (!pgd_present(*pgd_k))
			goto no_context;
		set_pgd(pgd, *pgd_k);
		
		pmd = pmd_offset(pgd, address);
		pmd_k = pmd_offset(pgd_k, address);
		if (!pmd_present(*pmd_k))
			goto no_context;
		set_pmd(pmd, *pmd_k);
                XEN_flush_page_update_queue(); /* flush PMD update */

		pte_k = pte_offset(pmd_k, address);
		if (!pte_present(*pte_k))
			goto no_context;
		return;
	}
}
