#ifndef __ASM_MACH_IPI_H
#define __ASM_MACH_IPI_H

#include <asm/genapic.h>

void send_IPI_mask_bitmask(cpumask_t mask, int vector);
void send_IPI_mask_sequence(cpumask_t mask, int vector);

#define send_IPI_mask (genapic->send_ipi_mask)

#endif /* __ASM_MACH_IPI_H */
