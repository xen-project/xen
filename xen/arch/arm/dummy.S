#define DUMMY(x) \
	.globl x; \
x:	.word 0xe7f000f0 /* Undefined instruction */

#define  NOP(x) \
	.globl x; \
x:	mov pc, lr
	
/* PIRQ support */
DUMMY(nr_irqs_gsi);

/* Other */
DUMMY(send_timer_event);
DUMMY(share_xen_page_with_privileged_guests);
