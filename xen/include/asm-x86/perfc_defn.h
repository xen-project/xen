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

PERFCOUNTER(seg_fixups,             "segmentation fixups")

PERFCOUNTER(apic_timer,             "apic timer interrupts")

PERFCOUNTER(domain_page_tlb_flush,  "domain page tlb flushes")

PERFCOUNTER(calls_to_mmuext_op,         "calls to mmuext_op")
PERFCOUNTER(num_mmuext_ops,             "mmuext ops")
PERFCOUNTER(calls_to_mmu_update,        "calls to mmu_update")
PERFCOUNTER(num_page_updates,           "page updates")
PERFCOUNTER(calls_to_update_va,         "calls to update_va_map")
PERFCOUNTER(page_faults,            "page faults")
PERFCOUNTER(copy_user_faults,       "copy_user faults")

PERFCOUNTER(map_domain_page_count,  "map_domain_page count")
PERFCOUNTER(ptwr_emulations,        "writable pt emulations")

PERFCOUNTER(exception_fixed,        "pre-exception fixed")


/* Shadow counters */
PERFCOUNTER(shadow_alloc,          "calls to shadow_alloc")
PERFCOUNTER(shadow_alloc_tlbflush, "shadow_alloc flushed TLBs")

/* STATUS counters do not reset when 'P' is hit */
PERFSTATUS(shadow_alloc_count,         "number of shadow pages in use")
PERFCOUNTER(shadow_free,           "calls to shadow_free")
PERFCOUNTER(shadow_prealloc_1,     "shadow recycles old shadows")
PERFCOUNTER(shadow_prealloc_2,     "shadow recycles in-use shadows")
PERFCOUNTER(shadow_linear_map_failed, "shadow hit read-only linear map")
PERFCOUNTER(shadow_a_update,       "shadow A bit update")
PERFCOUNTER(shadow_ad_update,      "shadow A&D bit update")
PERFCOUNTER(shadow_fault,          "calls to shadow_fault")
PERFCOUNTER(shadow_fault_fast_gnp, "shadow_fault fast path n/p")
PERFCOUNTER(shadow_fault_fast_mmio, "shadow_fault fast path mmio")
PERFCOUNTER(shadow_fault_fast_fail, "shadow_fault fast path error")
PERFCOUNTER(shadow_fault_bail_bad_gfn, "shadow_fault guest bad gfn")
PERFCOUNTER(shadow_fault_bail_not_present, 
                                        "shadow_fault guest not-present")
PERFCOUNTER(shadow_fault_bail_nx,  "shadow_fault guest NX fault")
PERFCOUNTER(shadow_fault_bail_ro_mapping, "shadow_fault guest R/W fault")
PERFCOUNTER(shadow_fault_bail_user_supervisor, 
                                        "shadow_fault guest U/S fault")
PERFCOUNTER(shadow_fault_emulate_read, "shadow_fault emulates a read")
PERFCOUNTER(shadow_fault_emulate_write, "shadow_fault emulates a write")
PERFCOUNTER(shadow_fault_emulate_failed, "shadow_fault emulator fails")
PERFCOUNTER(shadow_fault_emulate_stack, "shadow_fault emulate stack write")
PERFCOUNTER(shadow_fault_mmio,     "shadow_fault handled as mmio")
PERFCOUNTER(shadow_fault_fixed,    "shadow_fault fixed fault")
PERFCOUNTER(shadow_ptwr_emulate,   "shadow causes ptwr to emulate")
PERFCOUNTER(shadow_validate_gl1e_calls, "calls to shadow_validate_gl1e")
PERFCOUNTER(shadow_validate_gl2e_calls, "calls to shadow_validate_gl2e")
PERFCOUNTER(shadow_validate_gl3e_calls, "calls to shadow_validate_gl3e")
PERFCOUNTER(shadow_validate_gl4e_calls, "calls to shadow_validate_gl4e")
PERFCOUNTER(shadow_hash_lookups,   "calls to shadow_hash_lookup")
PERFCOUNTER(shadow_hash_lookup_head, "shadow hash hit in bucket head")
PERFCOUNTER(shadow_hash_lookup_miss, "shadow hash misses")
PERFCOUNTER(shadow_get_shadow_status, "calls to get_shadow_status")
PERFCOUNTER(shadow_hash_inserts,   "calls to shadow_hash_insert")
PERFCOUNTER(shadow_hash_deletes,   "calls to shadow_hash_delete")
PERFCOUNTER(shadow_writeable,      "shadow removes write access")
PERFCOUNTER(shadow_writeable_h_1,  "shadow writeable: 32b w2k3")
PERFCOUNTER(shadow_writeable_h_2,  "shadow writeable: 32pae w2k3")
PERFCOUNTER(shadow_writeable_h_3,  "shadow writeable: 64b w2k3")
PERFCOUNTER(shadow_writeable_h_4,  "shadow writeable: 32b linux low")
PERFCOUNTER(shadow_writeable_h_5,  "shadow writeable: 32b linux high")
PERFCOUNTER(shadow_writeable_bf,   "shadow writeable brute-force")
PERFCOUNTER(shadow_mappings,       "shadow removes all mappings")
PERFCOUNTER(shadow_mappings_bf,    "shadow rm-mappings brute-force")
PERFCOUNTER(shadow_early_unshadow, "shadow unshadows for fork/exit")
PERFCOUNTER(shadow_unshadow,       "shadow unshadows a page")
PERFCOUNTER(shadow_up_pointer,     "shadow unshadow by up-pointer")
PERFCOUNTER(shadow_unshadow_bf,    "shadow unshadow brute-force")
PERFCOUNTER(shadow_get_page_fail,  "shadow_get_page_from_l1e failed")
PERFCOUNTER(shadow_guest_walk,     "shadow walks guest tables")
PERFCOUNTER(shadow_invlpg,         "shadow emulates invlpg")
PERFCOUNTER(shadow_invlpg_fault,   "shadow invlpg faults")


/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
