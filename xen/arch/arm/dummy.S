#define DUMMY(x) \
	.globl x; \
x:	.word 0xe7f000f0 /* Undefined instruction */

#define  NOP(x) \
	.globl x; \
x:	mov pc, lr
	
DUMMY(alloc_pirq_struct);
DUMMY(alloc_vcpu_guest_context);
DUMMY(arch_do_domctl);
DUMMY(arch_do_sysctl);
DUMMY(arch_do_vcpu_op);
DUMMY(arch_get_info_guest);
DUMMY(arch_get_xen_caps);
DUMMY(arch_memory_op);
DUMMY(arch_set_info_guest);
DUMMY(arch_vcpu_reset);
DUMMY(create_grant_host_mapping);
DUMMY(__cpu_die);
DUMMY(__cpu_disable);
DUMMY(__cpu_up);
DUMMY(do_get_pm_info);
DUMMY(domain_get_maximum_gpfn);
DUMMY(domain_relinquish_resources);
DUMMY(domain_set_time_offset);
DUMMY(dom_cow);
DUMMY(donate_page);
DUMMY(do_pm_op);
DUMMY(flush_tlb_mask);
DUMMY(free_vcpu_guest_context);
DUMMY(get_page);
DUMMY(get_page_type);
DUMMY(gmfn_to_mfn);
DUMMY(gnttab_clear_flag);
DUMMY(gnttab_mark_dirty);
DUMMY(hypercall_create_continuation);
DUMMY(iommu_map_page);
DUMMY(iommu_unmap_page);
DUMMY(is_iomem_page);
DUMMY(max_page);
DUMMY(node_online_map);
DUMMY(nr_irqs_gsi);
DUMMY(p2m_pod_decrease_reservation);
DUMMY(guest_physmap_mark_populate_on_demand);
DUMMY(page_get_owner_and_reference);
DUMMY(page_is_ram_type);
DUMMY(per_cpu__cpu_core_mask);
DUMMY(per_cpu__cpu_sibling_mask);
DUMMY(__per_cpu_offset);
DUMMY(pirq_guest_bind);
DUMMY(pirq_guest_unbind);
DUMMY(pirq_set_affinity);
DUMMY(put_page);
DUMMY(put_page_type);
DUMMY(replace_grant_host_mapping);
DUMMY(send_timer_event);
DUMMY(share_xen_page_with_privileged_guests);
DUMMY(smp_send_state_dump);
DUMMY(steal_page);
DUMMY(sync_vcpu_execstate);
DUMMY(__udelay);
NOP(update_vcpu_system_time);
DUMMY(vcpu_mark_events_pending);
DUMMY(vcpu_show_execution_state);
DUMMY(wallclock_time);
