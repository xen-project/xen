#include <linux/config.h>
#include <linux/version.h>

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>

#include <xen/platform-compat.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
static int system_state = 1;
EXPORT_SYMBOL(system_state);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
size_t strcspn(const char *s, const char *reject)
{
        const char *p;
        const char *r;
        size_t count = 0;

        for (p = s; *p != '\0'; ++p) {
                for (r = reject; *r != '\0'; ++r) {
                        if (*p == *r)
                                return count;
                }
                ++count;
        }

        return count;
}
EXPORT_SYMBOL(strcspn);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
/*
 * Map a vmalloc()-space virtual address to the physical page frame number.
 */
unsigned long vmalloc_to_pfn(void * vmalloc_addr)
{
        return page_to_pfn(vmalloc_to_page(vmalloc_addr));
}
EXPORT_SYMBOL(vmalloc_to_pfn);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout)
{
        might_sleep();

        spin_lock_irq(&x->wait.lock);
        if (!x->done) {
                DECLARE_WAITQUEUE(wait, current);

                wait.flags |= WQ_FLAG_EXCLUSIVE;
                __add_wait_queue_tail(&x->wait, &wait);
                do {
                        __set_current_state(TASK_UNINTERRUPTIBLE);
                        spin_unlock_irq(&x->wait.lock);
                        timeout = schedule_timeout(timeout);
                        spin_lock_irq(&x->wait.lock);
                        if (!timeout) {
                                __remove_wait_queue(&x->wait, &wait);
                                goto out;
                        }
                } while (!x->done);
                __remove_wait_queue(&x->wait, &wait);
        }
        x->done--;
out:
        spin_unlock_irq(&x->wait.lock);
        return timeout;
}
EXPORT_SYMBOL(wait_for_completion_timeout);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/*
    fake do_exit using complete_and_exit
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
asmlinkage NORET_TYPE void do_exit(long code)
#else
fastcall NORET_TYPE void do_exit(long code)
#endif
{
    complete_and_exit(NULL, code);
}
EXPORT_SYMBOL_GPL(do_exit);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
signed long schedule_timeout_interruptible(signed long timeout)
{
	__set_current_state(TASK_INTERRUPTIBLE);
	return schedule_timeout(timeout);
}
EXPORT_SYMBOL(schedule_timeout_interruptible);
#endif
