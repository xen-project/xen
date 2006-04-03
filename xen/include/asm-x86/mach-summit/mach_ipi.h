#ifndef __ASM_MACH_IPI_H
#define __ASM_MACH_IPI_H

void send_IPI_mask_sequence(cpumask_t mask, int vector);

static inline void send_IPI_mask(cpumask_t mask, int vector)
{
	send_IPI_mask_sequence(mask, vector);
}

#endif /* __ASM_MACH_IPI_H */
