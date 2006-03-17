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

void dump_stack(struct thread *thread)
{
    unsigned long *bottom = (unsigned long *)thread->stack + 2048; 
    unsigned long *pointer = (unsigned long *)thread->eps;
    int count;
    printk("The stack for \"%s\"\n", thread->name);
    for(count = 0; count < 15 && pointer < bottom; count ++)
    {
        printk("[0x%lx] 0x%lx\n", pointer, *pointer);
        pointer++;
    }
    
    if(pointer < bottom) printk("Not the whole stack printed\n");
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
                         :"=m" (prev->eps),"=m" (prev->eip),            \
                          "=S" (esi),"=D" (edi)             \
                         :"m" (next->eps),"m" (next->eip),              \
                          "2" (prev), "d" (next));                      \
} while (0)
#elif __x86_64__
/* FIXME */
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
/* The thread switching only works for i386 at the moment */    
#ifdef __i386__    
    if(prev != next) switch_threads(prev, next);
#endif    
}



void exit_thread(struct thread *thread)
{
    unsigned long flags;
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
    
    thread->eps = (unsigned long)thread->stack + 4096 * 2 - 4;
    /* Save pointer to the thread on the stack, used by current macro */
    *((unsigned long *)thread->stack) = (unsigned long)thread;
    *((unsigned long *)thread->eps) = (unsigned long)thread;
    thread->eps -= 4; 
    *((unsigned long *)thread->eps) = (unsigned long)data;
    
    /* No return address */
    thread->eps -= 4;
    *((unsigned long *)thread->eps) = (unsigned long)exit_thread;
    
    thread->eip = (unsigned long)function;
     
    /* Not runable, not exited */ 
    thread->flags = 0;
    set_runnable(thread);
    
    local_irq_save(flags);
    if(idle_thread != NULL)
        list_add_tail(&thread->thread_list, &idle_thread->thread_list); 
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
    __asm__ __volatile__("mov %0,%%esp\n\t"
                         "push %1\n\t" 
                         "ret"                                            
                         :"=m" (idle_thread->eps)
                         :"m" (idle_thread->eip));                          
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

    
/*    create_thread("1", th_f1, (void *)0x1234);    
    create_thread("2", th_f1, (void *)0x1234);    
    create_thread("3", th_f1, (void *)0x1234);    
    create_thread("4", th_f1, (void *)0x1234);    
    create_thread("5", th_f1, (void *)0x1234);    
    create_thread("6", th_f1, (void *)0x1234);    
    create_thread("second", th_f2, NULL);
*/   
}

