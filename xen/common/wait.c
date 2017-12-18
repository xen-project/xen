/******************************************************************************
 * wait.c
 * 
 * Sleep in hypervisor context for some event to occur.
 * 
 * Copyright (c) 2010, Keir Fraser <keir@xen.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/wait.h>
#include <xen/errno.h>

struct waitqueue_vcpu {
    struct list_head list;
    struct vcpu *vcpu;
#ifdef CONFIG_X86
    /*
     * Xen/x86 does not have per-vcpu hypervisor stacks. So we must save the
     * hypervisor context before sleeping (descheduling), setjmp/longjmp-style.
     */
    void *esp;
    char *stack;
    cpumask_t saved_affinity;
    unsigned int wakeup_cpu;
#endif
};

int init_waitqueue_vcpu(struct vcpu *v)
{
    struct waitqueue_vcpu *wqv;

    wqv = xzalloc(struct waitqueue_vcpu);
    if ( wqv == NULL )
        return -ENOMEM;

#ifdef CONFIG_X86
    wqv->stack = alloc_xenheap_page();
    if ( wqv->stack == NULL )
    {
        xfree(wqv);
        return -ENOMEM;
    }
#endif

    INIT_LIST_HEAD(&wqv->list);
    wqv->vcpu = v;

    v->waitqueue_vcpu = wqv;

    return 0;
}

void destroy_waitqueue_vcpu(struct vcpu *v)
{
    struct waitqueue_vcpu *wqv;

    wqv = v->waitqueue_vcpu;
    if ( wqv == NULL )
        return;

    BUG_ON(!list_empty(&wqv->list));
#ifdef CONFIG_X86
    free_xenheap_page(wqv->stack);
#endif
    xfree(wqv);

    v->waitqueue_vcpu = NULL;
}

void init_waitqueue_head(struct waitqueue_head *wq)
{
    spin_lock_init(&wq->lock);
    INIT_LIST_HEAD(&wq->list);
}

void destroy_waitqueue_head(struct waitqueue_head *wq)
{
    wake_up_all(wq);
}

void wake_up_nr(struct waitqueue_head *wq, unsigned int nr)
{
    struct waitqueue_vcpu *wqv;

    spin_lock(&wq->lock);

    while ( !list_empty(&wq->list) && nr-- )
    {
        wqv = list_entry(wq->list.next, struct waitqueue_vcpu, list);
        list_del_init(&wqv->list);
        vcpu_unpause(wqv->vcpu);
        put_domain(wqv->vcpu->domain);
    }

    spin_unlock(&wq->lock);
}

void wake_up_one(struct waitqueue_head *wq)
{
    wake_up_nr(wq, 1);
}

void wake_up_all(struct waitqueue_head *wq)
{
    wake_up_nr(wq, UINT_MAX);
}

#ifdef CONFIG_X86

static void __prepare_to_wait(struct waitqueue_vcpu *wqv)
{
    struct cpu_info *cpu_info = get_cpu_info();
    struct vcpu *curr = current;
    unsigned long dummy;
    u32 entry_vector = cpu_info->guest_cpu_user_regs.entry_vector;

    ASSERT(wqv->esp == 0);

    /* Save current VCPU affinity; force wakeup on *this* CPU only. */
    wqv->wakeup_cpu = smp_processor_id();
    cpumask_copy(&wqv->saved_affinity, curr->cpu_hard_affinity);
    if ( vcpu_set_hard_affinity(curr, cpumask_of(wqv->wakeup_cpu)) )
    {
        gdprintk(XENLOG_ERR, "Unable to set vcpu affinity\n");
        domain_crash_synchronous();
    }

    /* Hand-rolled setjmp(). */
    asm volatile (
        "push %%rax; push %%rbx; push %%rdx; push %%rbp;"
        "push %%r8;  push %%r9;  push %%r10; push %%r11;"
        "push %%r12; push %%r13; push %%r14; push %%r15;"

        "call 1f;"
        "1: addq $2f-1b,(%%rsp);"
        "sub %%esp,%%ecx;"
        "cmp %3,%%ecx;"
        "ja 3f;"
        "mov %%rsp,%%rsi;"

        /* check_wakeup_from_wait() longjmp()'s to this point. */
        "2: rep movsb;"
        "mov %%rsp,%%rsi;"
        "3: pop %%rax;"

        "pop %%r15; pop %%r14; pop %%r13; pop %%r12;"
        "pop %%r11; pop %%r10; pop %%r9;  pop %%r8;"
        "pop %%rbp; pop %%rdx; pop %%rbx; pop %%rax"
        : "=&S" (wqv->esp), "=&c" (dummy), "=&D" (dummy)
        : "i" (PAGE_SIZE), "0" (0), "1" (cpu_info), "2" (wqv->stack)
        : "memory" );

    if ( unlikely(wqv->esp == 0) )
    {
        gdprintk(XENLOG_ERR, "Stack too large in %s\n", __func__);
        domain_crash_synchronous();
    }

    cpu_info->guest_cpu_user_regs.entry_vector = entry_vector;
}

static void __finish_wait(struct waitqueue_vcpu *wqv)
{
    wqv->esp = NULL;
    (void)vcpu_set_hard_affinity(current, &wqv->saved_affinity);
}

void check_wakeup_from_wait(void)
{
    struct waitqueue_vcpu *wqv = current->waitqueue_vcpu;

    ASSERT(list_empty(&wqv->list));

    if ( likely(wqv->esp == NULL) )
        return;

    /* Check if we woke up on the wrong CPU. */
    if ( unlikely(smp_processor_id() != wqv->wakeup_cpu) )
    {
        /* Re-set VCPU affinity and re-enter the scheduler. */
        struct vcpu *curr = current;
        cpumask_copy(&wqv->saved_affinity, curr->cpu_hard_affinity);
        if ( vcpu_set_hard_affinity(curr, cpumask_of(wqv->wakeup_cpu)) )
        {
            gdprintk(XENLOG_ERR, "Unable to set vcpu affinity\n");
            domain_crash_synchronous();
        }
        wait(); /* takes us back into the scheduler */
    }

    /*
     * Hand-rolled longjmp().  Returns to the pointer on the top of
     * wqv->stack, and lands on a `rep movs` instruction.  All other GPRs are
     * restored from the stack, so are available for use here.
     */
    asm volatile (
        "mov %1,%%"__OP"sp; INDIRECT_JMP %[ip]"
        : : "S" (wqv->stack), "D" (wqv->esp),
          "c" ((char *)get_cpu_info() - (char *)wqv->esp),
          [ip] "r" (*(unsigned long *)wqv->stack)
        : "memory" );
    unreachable();
}

#else /* !CONFIG_X86 */

#define __prepare_to_wait(wqv) ((void)0)
#define __finish_wait(wqv) ((void)0)

#endif

void prepare_to_wait(struct waitqueue_head *wq)
{
    struct vcpu *curr = current;
    struct waitqueue_vcpu *wqv = curr->waitqueue_vcpu;

    ASSERT_NOT_IN_ATOMIC();
    __prepare_to_wait(wqv);

    ASSERT(list_empty(&wqv->list));
    spin_lock(&wq->lock);
    list_add_tail(&wqv->list, &wq->list);
    vcpu_pause_nosync(curr);
    get_knownalive_domain(curr->domain);
    spin_unlock(&wq->lock);
}

void finish_wait(struct waitqueue_head *wq)
{
    struct vcpu *curr = current;
    struct waitqueue_vcpu *wqv = curr->waitqueue_vcpu;

    __finish_wait(wqv);

    if ( list_empty(&wqv->list) )
        return;

    spin_lock(&wq->lock);
    if ( !list_empty(&wqv->list) )
    {
        list_del_init(&wqv->list);
        vcpu_unpause(curr);
        put_domain(curr->domain);
    }
    spin_unlock(&wq->lock);
}
