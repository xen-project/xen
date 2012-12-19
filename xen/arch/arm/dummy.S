#define DUMMY(x) \
	.globl x; \
x:	.word 0xe7f000f0 /* Undefined instruction */

#define  NOP(x) \
	.globl x; \
x:	mov pc, lr
	
/* PIRQ support */
DUMMY(alloc_pirq_struct);
DUMMY(nr_irqs_gsi);
DUMMY(pirq_guest_bind);
DUMMY(pirq_guest_unbind);
DUMMY(pirq_set_affinity);

/* VCPU */
NOP(update_vcpu_system_time);

/* Grant Tables */
DUMMY(steal_page);

/* Page Offlining */
DUMMY(page_is_ram_type);

/* Other */
DUMMY(domain_get_maximum_gpfn);
DUMMY(domain_relinquish_resources);
DUMMY(domain_set_time_offset);
DUMMY(dom_cow);
DUMMY(send_timer_event);
DUMMY(share_xen_page_with_privileged_guests);
DUMMY(wallclock_time);
