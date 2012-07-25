#define DUMMY(x) \
	.globl x; \
x:	.word 0xe7f000f0 /* Undefined instruction */

#define  NOP(x) \
	.globl x; \
x:	mov pc, lr
	
/* SMP support */
DUMMY(node_online_map);
DUMMY(smp_send_state_dump);

/* PIRQ support */
DUMMY(alloc_pirq_struct);
DUMMY(nr_irqs_gsi);
DUMMY(pirq_guest_bind);
DUMMY(pirq_guest_unbind);
DUMMY(pirq_set_affinity);

/* VCPU */
DUMMY(arch_get_info_guest);
DUMMY(arch_vcpu_reset);
NOP(update_vcpu_system_time);

/* Page Reference & Type Maintenance */
DUMMY(get_page);
DUMMY(get_page_type);
DUMMY(page_get_owner_and_reference);
DUMMY(put_page);
DUMMY(put_page_type);

/* Grant Tables */
DUMMY(create_grant_host_mapping);
DUMMY(gnttab_clear_flag);
DUMMY(gnttab_mark_dirty);
DUMMY(is_iomem_page);
DUMMY(replace_grant_host_mapping);
DUMMY(steal_page);

/* Page Offlining */
DUMMY(page_is_ram_type);

/* Other */
DUMMY(domain_get_maximum_gpfn);
DUMMY(domain_relinquish_resources);
DUMMY(domain_set_time_offset);
DUMMY(dom_cow);
DUMMY(gmfn_to_mfn);
DUMMY(send_timer_event);
DUMMY(share_xen_page_with_privileged_guests);
DUMMY(wallclock_time);
