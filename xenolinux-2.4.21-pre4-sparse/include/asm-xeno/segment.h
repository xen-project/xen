#ifndef _ASM_SEGMENT_H
#define _ASM_SEGMENT_H

#include <asm/hypervisor-ifs/hypervisor-if.h>

#define __KERNEL_CS	FLAT_RING1_CS
#define __KERNEL_DS	FLAT_RING1_DS

#define __USER_CS	FLAT_RING3_CS
#define __USER_DS	FLAT_RING3_DS

#endif
