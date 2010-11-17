/******************************************************************************
 * wait.c
 * 
 * Sleep in hypervisor context for some event to occur.
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/wait.h>

struct waitqueue_vcpu {
    struct list_head list;
    struct vcpu *vcpu;
#ifdef CONFIG_X86
    /*
     * Xen/x86 does not have per-vcpu hypervisor stacks. So we must save the
     * hypervisor context before sleeping (descheduling), setjmp/longjmp-style.
     */
    void *esp;
    char stack[1500];
#endif
};

int init_waitqueue_vcpu(struct vcpu *v)
{
    struct waitqueue_vcpu *wqv;

    wqv = xmalloc(struct waitqueue_vcpu);
    if ( wqv == NULL )
        return -ENOMEM;

    memset(wqv, 0, sizeof(*wqv));
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
    xfree(wqv);

    v->waitqueue_vcpu = NULL;
}

void init_waitqueue_head(struct waitqueue_head *wq)
{
    spin_lock_init(&wq->lock);
    INIT_LIST_HEAD(&wq->list);
}

void wake_up(struct waitqueue_head *wq)
{
    struct waitqueue_vcpu *wqv;

    spin_lock(&wq->lock);

    while ( !list_empty(&wq->list) )
    {
        wqv = list_entry(wq->list.next, struct waitqueue_vcpu, list);
        list_del_init(&wqv->list);
        vcpu_unpause(wqv->vcpu);
    }

    spin_unlock(&wq->lock);
}

#ifdef CONFIG_X86

static void __prepare_to_wait(struct waitqueue_vcpu *wqv)
{
    char *cpu_info = (char *)get_cpu_info();
    asm volatile (
#ifdef CONFIG_X86_64
        "push %%rax; push %%rbx; push %%rcx; push %%rdx; push %%rdi; "
        "push %%rbp; push %%r8; push %%r9; push %%r10; push %%r11; "
        "push %%r12; push %%r13; push %%r14; push %%r15; call 1f; "
        "1: mov 80(%%rsp),%%rdi; mov 96(%%rsp),%%rcx; mov %%rsp,%%rsi; "
        "sub %%rsi,%%rcx; rep movsb; mov %%rsp,%%rsi; pop %%rax; "
        "pop %%r15; pop %%r14; pop %%r13; pop %%r12; "
        "pop %%r11; pop %%r10; pop %%r9; pop %%r8; "
        "pop %%rbp; pop %%rdi; pop %%rdx; pop %%rcx; pop %%rbx; pop %%rax"
#else
        "push %%eax; push %%ebx; push %%ecx; push %%edx; push %%edi; "
        "push %%ebp; call 1f; "
        "1: mov 8(%%esp),%%edi; mov 16(%%esp),%%ecx; mov %%esp,%%esi; "
        "sub %%esi,%%ecx; rep movsb; mov %%esp,%%esi; pop %%eax; "
        "pop %%ebp; pop %%edi; pop %%edx; pop %%ecx; pop %%ebx; pop %%eax"
#endif
        : "=S" (wqv->esp)
        : "c" (cpu_info), "D" (wqv->stack)
        : "memory" );
    BUG_ON((cpu_info - (char *)wqv->esp) > sizeof(wqv->stack));
}

static void __finish_wait(struct waitqueue_vcpu *wqv)
{
    wqv->esp = NULL;
}

void check_wakeup_from_wait(void)
{
    struct waitqueue_vcpu *wqv = current->waitqueue_vcpu;

    ASSERT(list_empty(&wqv->list));

    if ( likely(wqv->esp == NULL) )
        return;

    asm volatile (
        "mov %1,%%"__OP"sp; rep movsb; jmp *(%%"__OP"sp)"
        : : "S" (wqv->stack), "D" (wqv->esp),
        "c" ((char *)get_cpu_info() - (char *)wqv->esp)
        : "memory" );
}

#else /* !CONFIG_X86 */

#define __prepare_to_wait(wqv) ((void)0)
#define __finish_wait(wqv) ((void)0)

#endif

void prepare_to_wait(struct waitqueue_head *wq)
{
    struct vcpu *curr = current;
    struct waitqueue_vcpu *wqv = curr->waitqueue_vcpu;

    ASSERT(list_empty(&wqv->list));

    spin_lock(&wq->lock);
    list_add_tail(&wqv->list, &wq->list);
    vcpu_pause_nosync(curr);
    spin_unlock(&wq->lock);

    __prepare_to_wait(wqv);
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
    }
    spin_unlock(&wq->lock);
}
