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


/* Shadow counters */
PERFCOUNTER_CPU(shadow_alloc,          "calls to shadow_alloc")
PERFCOUNTER_CPU(shadow_alloc_tlbflush, "shadow_alloc flushed TLBs")

/* STATUS counters do not reset when 'P' is hit */
PERFSTATUS(shadow_alloc_count,         "number of shadow pages in use")
PERFCOUNTER_CPU(shadow_free,           "calls to shadow_free")
PERFCOUNTER_CPU(shadow_prealloc_1,     "shadow recycles old shadows")
PERFCOUNTER_CPU(shadow_prealloc_2,     "shadow recycles in-use shadows")
PERFCOUNTER_CPU(shadow_linear_map_failed, "shadow hit read-only linear map")
PERFCOUNTER_CPU(shadow_a_update,       "shadow A bit update")
PERFCOUNTER_CPU(shadow_ad_update,      "shadow A&D bit update")
PERFCOUNTER_CPU(shadow_fault,          "calls to shadow_fault")
PERFCOUNTER_CPU(shadow_fault_fast_gnp, "shadow_fault fast path n/p")
PERFCOUNTER_CPU(shadow_fault_fast_mmio, "shadow_fault fast path mmio")
PERFCOUNTER_CPU(shadow_fault_fast_fail, "shadow_fault fast path error")
PERFCOUNTER_CPU(shadow_fault_bail_bad_gfn, "shadow_fault guest bad gfn")
PERFCOUNTER_CPU(shadow_fault_bail_not_present, 
                                        "shadow_fault guest not-present")
PERFCOUNTER_CPU(shadow_fault_bail_nx,  "shadow_fault guest NX fault")
PERFCOUNTER_CPU(shadow_fault_bail_ro_mapping, "shadow_fault guest R/W fault")
PERFCOUNTER_CPU(shadow_fault_bail_user_supervisor, 
                                        "shadow_fault guest U/S fault")
PERFCOUNTER_CPU(shadow_fault_emulate_read, "shadow_fault emulates a read")
PERFCOUNTER_CPU(shadow_fault_emulate_write, "shadow_fault emulates a write")
PERFCOUNTER_CPU(shadow_fault_emulate_failed, "shadow_fault emulator fails")
PERFCOUNTER_CPU(shadow_fault_emulate_stack, "shadow_fault emulate stack write")
PERFCOUNTER_CPU(shadow_fault_mmio,     "shadow_fault handled as mmio")
PERFCOUNTER_CPU(shadow_fault_fixed,    "shadow_fault fixed fault")
PERFCOUNTER_CPU(shadow_ptwr_emulate,   "shadow causes ptwr to emulate")
PERFCOUNTER_CPU(shadow_validate_gl1e_calls, "calls to shadow_validate_gl1e")
PERFCOUNTER_CPU(shadow_validate_gl2e_calls, "calls to shadow_validate_gl2e")
PERFCOUNTER_CPU(shadow_validate_gl3e_calls, "calls to shadow_validate_gl3e")
PERFCOUNTER_CPU(shadow_validate_gl4e_calls, "calls to shadow_validate_gl4e")
PERFCOUNTER_CPU(shadow_hash_lookups,   "calls to shadow_hash_lookup")
PERFCOUNTER_CPU(shadow_hash_lookup_head, "shadow hash hit in bucket head")
PERFCOUNTER_CPU(shadow_hash_lookup_miss, "shadow hash misses")
PERFCOUNTER_CPU(shadow_get_shadow_status, "calls to get_shadow_status")
PERFCOUNTER_CPU(shadow_hash_inserts,   "calls to shadow_hash_insert")
PERFCOUNTER_CPU(shadow_hash_deletes,   "calls to shadow_hash_delete")
PERFCOUNTER_CPU(shadow_writeable,      "shadow removes write access")
PERFCOUNTER_CPU(shadow_writeable_h_1,  "shadow writeable: 32b w2k3")
PERFCOUNTER_CPU(shadow_writeable_h_2,  "shadow writeable: 32pae w2k3")
PERFCOUNTER_CPU(shadow_writeable_h_3,  "shadow writeable: 64b w2k3")
PERFCOUNTER_CPU(shadow_writeable_h_4,  "shadow writeable: 32b linux low")
PERFCOUNTER_CPU(shadow_writeable_h_5,  "shadow writeable: 32b linux high")
PERFCOUNTER_CPU(shadow_writeable_bf,   "shadow writeable brute-force")
PERFCOUNTER_CPU(shadow_mappings,       "shadow removes all mappings")
PERFCOUNTER_CPU(shadow_mappings_bf,    "shadow rm-mappings brute-force")
PERFCOUNTER_CPU(shadow_early_unshadow, "shadow unshadows for fork/exit")
PERFCOUNTER_CPU(shadow_unshadow,       "shadow unshadows a page")
PERFCOUNTER_CPU(shadow_up_pointer,     "shadow unshadow by up-pointer")
PERFCOUNTER_CPU(shadow_unshadow_bf,    "shadow unshadow brute-force")
PERFCOUNTER_CPU(shadow_get_page_fail,  "shadow_get_page_from_l1e failed")
PERFCOUNTER_CPU(shadow_guest_walk,     "shadow walks guest tables")
PERFCOUNTER_CPU(shadow_invlpg,         "shadow emulates invlpg")
PERFCOUNTER_CPU(shadow_invlpg_fault,   "shadow invlpg faults")


/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
