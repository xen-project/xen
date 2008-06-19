#include <linux/module.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <asm/hypervisor.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

MODULE_LICENSE("GPL");

#ifdef __ia64__
static void
xen_panic_hypercall(struct unw_frame_info *info, void *arg)
{
	current->thread.ksp = (__u64)info->sw - 16;
	HYPERVISOR_shutdown(SHUTDOWN_crash);
	/* we're never actually going to get here... */
}
#endif

static int
xen_panic_event(struct notifier_block *this, unsigned long event, void *ptr)
{
#ifdef __ia64__
	unw_init_running(xen_panic_hypercall, NULL);
#else /* !__ia64__ */
	HYPERVISOR_shutdown(SHUTDOWN_crash);
#endif
	/* we're never actually going to get here... */
	return NOTIFY_DONE;
}

static struct notifier_block xen_panic_block = {
	.notifier_call = xen_panic_event
};

int xen_panic_handler_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &xen_panic_block);
	return 0;
}
