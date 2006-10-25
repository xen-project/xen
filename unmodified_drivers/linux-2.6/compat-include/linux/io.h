#ifndef _LINUX_IO_H
#define _LINUX_IO_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#error "This version of Linux should not need compat linux/io.h"
#endif

#include <asm/io.h>

#endif
