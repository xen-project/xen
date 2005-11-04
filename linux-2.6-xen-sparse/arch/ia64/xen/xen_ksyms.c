/*
 * Architecture-specific kernel symbols
 *
 * Don't put any exports here unless it's defined in an assembler file.
 * All other exports should be put directly after the definition.
 */

#include <linux/config.h>
#include <linux/module.h>

extern int is_running_on_xen(void);
EXPORT_SYMBOL(is_running_on_xen);
