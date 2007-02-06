/* 
 ****************************************************************************
 * (C) 2005 - Grzegorz Milos - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: sched.c
 *      Author: Grzegorz Milos
 *     Changes: Robert Kaiser
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

struct thread *idle_thread = NULL;
LIST_HEAD(exited_threads);

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

/* Find the time when the next timeout expires. If this is more than
   10 seconds from now, return 10 seconds from now. */
static s_time_t blocking_time(void)
{
    struct thread *thread;
    struct list_head *iterator;
    s_time_t min_wakeup_time;
    unsigned long flags;
    local_irq_save(flags);
    /* default-block the domain for 10 seconds: */
    min_wakeup_time = NOW() + SECONDS(10);

    /* Thread list needs to be protected */
    list_for_each(iterator, &idle_thread->thread_list)
    {
        thread = list_entry(iterator, struct thread, thread_list);
        if(!is_runnable(thread) && thread->wakeup_time != 0LL)
        {
            if(thread->wakeup_time < min_wakeup_time)
            {
                min_wakeup_time = thread->wakeup_time;
            }
        }
    }
    local_irq_restore(flags);
    return(min_wakeup_time);
}

/* Wake up all threads with expired timeouts. */
static void wake_expired(void)
{
    struct thread *thread;
    struct list_head *iterator;
    s_time_t now = NOW();
    unsigned long flags;
    local_irq_save(flags);
    /* Thread list needs to be protected */
    list_for_each(iterator, &idle_thread->thread_list)
    {
        thread = list_entry(iterator, struct thread, thread_list);
        if(!is_runnable(thread) && thread->wakeup_time != 0LL)
        {
            if(thread->wakeup_time <= now)
                wake(thread);
        }
    }
    local_irq_restore(flags);
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

struct thread* create_thread(char *name, void (*function)(void *), void *data)
{
    struct thread *thread;
    unsigned long flags;
    /* Call architecture specific setup. */
    thread = arch_create_thread(name, function, data);
    /* Not runable, not exited, not sleeping */
    thread->flags = 0;
    thread->wakeup_time = 0LL;
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

void block(struct thread *thread)
{
    thread->wakeup_time = 0LL;
    clear_runnable(thread);
}

void sleep(u32 millisecs)
{
    struct thread *thread = get_current();
    thread->wakeup_time = NOW()  + MILLISECS(millisecs);
    clear_runnable(thread);
    schedule();
}

void wake(struct thread *thread)
{
    thread->wakeup_time = 0LL;
    set_runnable(thread);
}

void idle_thread_fn(void *unused)
{
    s_time_t until;
    for(;;)
    {
        schedule();
        /* block until the next timeout expires, or for 10 secs, whichever comes first */
        until = blocking_time();
        block_domain(until);
        wake_expired();
    }
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

