#include <linux/config.h>
#include <linux/version.h>

#include <linux/module.h>

#include <xen/platform-compat.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
static int system_state = 1;
EXPORT_SYMBOL(system_state);
#endif
