/* This file is legitimately included multiple times. */
/*#ifndef __XEN_PERFC_DEFN_H__*/
/*#define __XEN_PERFC_DEFN_H__*/

PERFCOUNTER_ARRAY(exceptions,           "exceptions", 32)

#define VMX_PERF_EXIT_REASON_SIZE 44
#define VMX_PERF_VECTOR_SIZE 0x20
PERFCOUNTER_ARRAY(vmexits,              "vmexits", VMX_PERF_EXIT_REASON_SIZE)
PERFCOUNTER_ARRAY(cause_vector,         "cause vector", VMX_PERF_VECTOR_SIZE)

#define SVM_PERF_EXIT_REASON_SIZE (1+136)
PERFCOUNTER_ARRAY(svmexits,             "SVMexits", SVM_PERF_EXIT_REASON_SIZE)

PERFCOUNTER_CPU(seg_fixups,             "segmentation fixups")

PERFCOUNTER_CPU(apic_timer,             "apic timer interrupts")

PERFCOUNTER_CPU(domain_page_tlb_flush,  "domain page tlb flushes")

PERFCOUNTER_CPU(calls_to_mmu_update,    "calls_to_mmu_update")
PERFCOUNTER_CPU(num_page_updates,       "num_page_updates")
PERFCOUNTER_CPU(calls_to_update_va,     "calls_to_update_va_map")
PERFCOUNTER_CPU(page_faults,            "page faults")
PERFCOUNTER_CPU(copy_user_faults,       "copy_user faults")

PERFCOUNTER_CPU(map_domain_page_count,  "map_domain_page count")
PERFCOUNTER_CPU(ptwr_emulations,        "writable pt emulations")

PERFCOUNTER_CPU(exception_fixed,        "pre-exception fixed")


/* Shadow2 counters */
PERFCOUNTER_CPU(shadow2_alloc,          "calls to shadow2_alloc")
PERFCOUNTER_CPU(shadow2_alloc_tlbflush, "shadow2_alloc flushed TLBs")

/* STATUS counters do not reset when 'P' is hit */
PERFSTATUS(shadow2_alloc_count,         "number of shadow pages in use")
PERFCOUNTER_CPU(shadow2_free,           "calls to shadow2_free")
PERFCOUNTER_CPU(shadow2_prealloc_1,     "shadow2 recycles old shadows")
PERFCOUNTER_CPU(shadow2_prealloc_2,     "shadow2 recycles in-use shadows")
PERFCOUNTER_CPU(shadow2_linear_map_failed, "shadow2 hit read-only linear map")
PERFCOUNTER_CPU(shadow2_a_update,       "shadow2 A bit update")
PERFCOUNTER_CPU(shadow2_ad_update,      "shadow2 A&D bit update")
PERFCOUNTER_CPU(shadow2_fault,          "calls to shadow2_fault")
PERFCOUNTER_CPU(shadow2_fault_bail_bad_gfn, "shadow2_fault guest bad gfn")
PERFCOUNTER_CPU(shadow2_fault_bail_not_present, 
                                        "shadow2_fault guest not-present")
PERFCOUNTER_CPU(shadow2_fault_bail_nx,  "shadow2_fault guest NX fault")
PERFCOUNTER_CPU(shadow2_fault_bail_ro_mapping, "shadow2_fault guest R/W fault")
PERFCOUNTER_CPU(shadow2_fault_bail_user_supervisor, 
                                        "shadow2_fault guest U/S fault")
PERFCOUNTER_CPU(shadow2_fault_emulate_read, "shadow2_fault emulates a read")
PERFCOUNTER_CPU(shadow2_fault_emulate_write, "shadow2_fault emulates a write")
PERFCOUNTER_CPU(shadow2_fault_emulate_failed, "shadow2_fault emulator fails")
PERFCOUNTER_CPU(shadow2_fault_mmio,     "shadow2_fault handled as mmio")
PERFCOUNTER_CPU(shadow2_fault_fixed,    "shadow2_fault fixed fault")
PERFCOUNTER_CPU(shadow2_ptwr_emulate,   "shadow2 causes ptwr to emulate")
PERFCOUNTER_CPU(shadow2_validate_gl1e_calls, "calls to shadow2_validate_gl1e")
PERFCOUNTER_CPU(shadow2_validate_gl2e_calls, "calls to shadow2_validate_gl2e")
PERFCOUNTER_CPU(shadow2_validate_gl3e_calls, "calls to shadow2_validate_gl3e")
PERFCOUNTER_CPU(shadow2_validate_gl4e_calls, "calls to shadow2_validate_gl4e")
PERFCOUNTER_CPU(shadow2_hash_lookups,   "calls to shadow2_hash_lookup")
PERFCOUNTER_CPU(shadow2_hash_lookup_head, "shadow2 hash hit in bucket head")
PERFCOUNTER_CPU(shadow2_hash_lookup_miss, "shadow2 hash misses")
PERFCOUNTER_CPU(shadow2_get_shadow_status, "calls to get_shadow_status")
PERFCOUNTER_CPU(shadow2_hash_inserts,   "calls to shadow2_hash_insert")
PERFCOUNTER_CPU(shadow2_hash_deletes,   "calls to shadow2_hash_delete")
PERFCOUNTER_CPU(shadow2_writeable,      "shadow2 removes write access")
PERFCOUNTER_CPU(shadow2_writeable_h_1,  "shadow2 writeable: 32b w2k3")
PERFCOUNTER_CPU(shadow2_writeable_h_2,  "shadow2 writeable: 32pae w2k3")
PERFCOUNTER_CPU(shadow2_writeable_h_3,  "shadow2 writeable: 64b w2k3")
PERFCOUNTER_CPU(shadow2_writeable_h_4,  "shadow2 writeable: 32b linux low")
PERFCOUNTER_CPU(shadow2_writeable_bf,   "shadow2 writeable brute-force")
PERFCOUNTER_CPU(shadow2_mappings,       "shadow2 removes all mappings")
PERFCOUNTER_CPU(shadow2_mappings_bf,    "shadow2 rm-mappings brute-force")
PERFCOUNTER_CPU(shadow2_early_unshadow, "shadow2 unshadows for fork/exit")
PERFCOUNTER_CPU(shadow2_early_unshadow_top, "shadow2 unhooks for fork/exit")
PERFCOUNTER_CPU(shadow2_unshadow,       "shadow2 unshadows a page")
PERFCOUNTER_CPU(shadow2_up_pointer,     "shadow2 unshadow by up-pointer")
PERFCOUNTER_CPU(shadow2_unshadow_bf,    "shadow2 unshadow brute-force")
PERFCOUNTER_CPU(shadow2_get_page_fail,  "shadow2_get_page_from_l1e failed")
PERFCOUNTER_CPU(shadow2_guest_walk,     "shadow2 walks guest tables")
PERFCOUNTER_CPU(shadow2_walk_cache_hit, "shadow2 walk-cache hits")
PERFCOUNTER_CPU(shadow2_walk_cache_miss, "shadow2 walk-cache misses")


/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
