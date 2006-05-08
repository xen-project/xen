/* 
 ****************************************************************************
 * (C) 2005 - Grzegorz Milos - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: sched.c
 *      Author: Grzegorz Milos
 *     Changes: 
 *              
 *        Date: Aug 2005
 * 
 * Environment: Xen Minimal OS
 * Description: simple scheduler for Mini-Os
 *
 * The scheduler is non-preemptive (cooperative), and schedules according 
 * to Round Robin algorithm.
 *
 ****************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <os.h>
#include <hypervisor.h>
#include <time.h>
#include <mm.h>
#include <types.h>
#include <lib.h>
#include <xmalloc.h>
#include <list.h>
#include <sched.h>
#include <semaphore.h>


#ifdef SCHED_DEBUG
#define DEBUG(_f, _a...) \
    printk("MINI_OS(file=sched.c, line=%d) " _f "\n", __LINE__, ## _a)
#else
#define DEBUG(_f, _a...)    ((void)0)
#endif


#define RUNNABLE_FLAG   0x00000001

#define is_runnable(_thread)    (_thread->flags & RUNNABLE_FLAG)
#define set_runnable(_thread)   (_thread->flags |= RUNNABLE_FLAG)
#define clear_runnable(_thread) (_thread->flags &= ~RUNNABLE_FLAG)


struct thread *idle_thread = NULL;
LIST_HEAD(exited_threads);

void idle_thread_fn(void *unused);

void dump_stack(struct thread *thread)
{
    unsigned long *bottom = (unsigned long *)(thread->stack + 2*4*1024); 
    unsigned long *pointer = (unsigned long *)thread->sp;
    int count;
    if(thread == current)
    {
#ifdef __i386__    
        asm("movl %%esp,%0"
            : "=r"(pointer));
#else
        asm("movq %%rsp,%0"
            : "=r"(pointer));
#endif
    }
    printk("The stack for \"%s\"\n", thread->name);
    for(count = 0; count < 25 && pointer < bottom; count ++)
    {
        printk("[0x%lx] 0x%lx\n", pointer, *pointer);
        pointer++;
    }
    
    if(pointer < bottom) printk(" ... continues.\n");
}

#ifdef __i386__
#define switch_threads(prev, next) do {                                 \
    unsigned long esi,edi;                                              \
    __asm__ __volatile__("pushfl\n\t"                                   \
                         "pushl %%ebp\n\t"                              \
                         "movl %%esp,%0\n\t"         /* save ESP */     \
                         "movl %4,%%esp\n\t"        /* restore ESP */   \
                         "movl $1f,%1\n\t"          /* save EIP */      \
                         "pushl %5\n\t"             /* restore EIP */   \
                         "ret\n\t"                                      \
                         "1:\t"                                         \
                         "popl %%ebp\n\t"                               \
                         "popfl"                                        \
                         :"=m" (prev->sp),"=m" (prev->ip),            \
                          "=S" (esi),"=D" (edi)             \
                         :"m" (next->sp),"m" (next->ip),              \
                          "2" (prev), "d" (next));                      \
} while (0)
#elif __x86_64__
#define switch_threads(prev, next) do {                                 \
    unsigned long rsi,rdi;                                              \
    __asm__ __volatile__("pushfq\n\t"                                   \
                         "pushq %%rbp\n\t"                              \
                         "movq %%rsp,%0\n\t"         /* save RSP */     \
                         "movq %4,%%rsp\n\t"        /* restore RSP */   \
                         "movq $1f,%1\n\t"          /* save RIP */      \
                         "pushq %5\n\t"             /* restore RIP */   \
                         "ret\n\t"                                      \
                         "1:\t"                                         \
                         "popq %%rbp\n\t"                               \
                         "popfq"                                        \
                         :"=m" (prev->sp),"=m" (prev->ip),            \
                          "=S" (rsi),"=D" (rdi)             \
                         :"m" (next->sp),"m" (next->ip),              \
                          "2" (prev), "d" (next));                      \
} while (0)
#endif

void inline print_runqueue(void)
{
    struct list_head *it;
    struct thread *th;
    list_for_each(it, &idle_thread->thread_list)
    {
        th = list_entry(it, struct thread, thread_list);
        printk("   Thread \"%s\", runnable=%d\n", th->name, is_runnable(th));
    }
    printk("\n");
}


void schedule(void)
{
    struct thread *prev, *next, *thread;
    struct list_head *iterator;
    unsigned long flags;
    prev = current;
    local_irq_save(flags); 
    list_for_each(iterator, &exited_threads)
    {
        thread = list_entry(iterator, struct thread, thread_list);
        if(thread != prev)
        {
            list_del(&thread->thread_list);
            free_pages(thread->stack, 1);
            xfree(thread);
        }
    }
    next = idle_thread;   
    /* Thread list needs to be protected */
    list_for_each(iterator, &idle_thread->thread_list)
    {
        thread = list_entry(iterator, struct thread, thread_list);
        if(is_runnable(thread)) 
        {
            next = thread;
            /* Put this thread on the end of the list */
            list_del(&thread->thread_list);
            list_add_tail(&thread->thread_list, &idle_thread->thread_list);
            break;
        }
    }
    local_irq_restore(flags);
    /* Interrupting the switch is equivalent to having the next thread
       inturrupted at the return instruction. And therefore at safe point. */
    if(prev != next) switch_threads(prev, next);
}


/* Gets run when a new thread is scheduled the first time ever, 
   defined in x86_[32/64].S */
extern void thread_starter(void);


void exit_thread(void)
{
    unsigned long flags;
    struct thread *thread = current;
    printk("Thread \"%s\" exited.\n", thread->name);
    local_irq_save(flags);
    /* Remove from the thread list */
    list_del(&thread->thread_list);
    clear_runnable(thread);
    /* Put onto exited list */
    list_add(&thread->thread_list, &exited_threads);
    local_irq_restore(flags);
    /* Schedule will free the resources */
    schedule();
}

/* Pushes the specified value onto the stack of the specified thread */
static void stack_push(struct thread *thread, unsigned long value)
{
    thread->sp -= sizeof(unsigned long);
    *((unsigned long *)thread->sp) = value;
}

struct thread* create_thread(char *name, void (*function)(void *), void *data)
{
    struct thread *thread;
    unsigned long flags;
    
    thread = xmalloc(struct thread);
    /* Allocate 2 pages for stack, stack will be 2pages aligned */
    thread->stack = (char *)alloc_pages(1);
    thread->name = name;
    printk("Thread \"%s\": pointer: 0x%lx, stack: 0x%lx\n", name, thread, 
            thread->stack);
    
    thread->sp = (unsigned long)thread->stack + 4096 * 2;
    /* Save pointer to the thread on the stack, used by current macro */
    *((unsigned long *)thread->stack) = (unsigned long)thread;
    
    stack_push(thread, (unsigned long) function);
    stack_push(thread, (unsigned long) data);
    thread->ip = (unsigned long) thread_starter;
     
    /* Not runable, not exited */ 
    thread->flags = 0;
    set_runnable(thread);
    local_irq_save(flags);
    if(idle_thread != NULL) {
        list_add_tail(&thread->thread_list, &idle_thread->thread_list); 
    } else if(function != idle_thread_fn)
    {
        printk("BUG: Not allowed to create thread before initialising scheduler.\n");
        BUG();
    }
    local_irq_restore(flags);
    return thread;
}


void block(struct thread *thread)
{
    clear_runnable(thread);
}

void wake(struct thread *thread)
{
    set_runnable(thread);
}

void idle_thread_fn(void *unused)
{
    for(;;)
    {
        schedule();
        block_domain(10000);
    }
}

void run_idle_thread(void)
{
    /* Switch stacks and run the thread */ 
#if defined(__i386__)
    __asm__ __volatile__("mov %0,%%esp\n\t"
                         "push %1\n\t" 
                         "ret"                                            
                         :"=m" (idle_thread->sp)
                         :"m" (idle_thread->ip));                          
#elif defined(__x86_64__)
    __asm__ __volatile__("mov %0,%%rsp\n\t"
                         "push %1\n\t" 
                         "ret"                                            
                         :"=m" (idle_thread->sp)
                         :"m" (idle_thread->ip));                          
#endif
}



DECLARE_MUTEX(mutex);

void th_f1(void *data)
{
    struct timeval tv1, tv2;

    for(;;)
    {
        down(&mutex);
        printk("Thread \"%s\" got semaphore, runnable %d\n", current->name, is_runnable(current));
        schedule();
        printk("Thread \"%s\" releases the semaphore\n", current->name);
        up(&mutex);
        
        
        gettimeofday(&tv1);
        for(;;)
        {
            gettimeofday(&tv2);
            if(tv2.tv_sec - tv1.tv_sec > 2) break;
        }
                
        
        schedule(); 
    }
}

void th_f2(void *data)
{
    for(;;)
    {
        printk("Thread OTHER executing, data 0x%lx\n", data);
        schedule();
    }
}



void init_sched(void)
{
    printk("Initialising scheduler\n");

    idle_thread = create_thread("Idle", idle_thread_fn, NULL);
    INIT_LIST_HEAD(&idle_thread->thread_list);
}

