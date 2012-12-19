#define DUMMY(x) \
	.globl x; \
x:	.word 0xe7f000f0 /* Undefined instruction */

#define  NOP(x) \
	.globl x; \
x:	mov pc, lr
	
/* PIRQ support */
DUMMY(nr_irqs_gsi);
