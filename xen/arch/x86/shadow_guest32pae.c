#define GUEST_32PAE
#if defined (__x86_64__)

#include "shadow.c"
struct shadow_ops MODE_64_PAE_HANDLER = {
    .guest_paging_levels              = 3,
    .invlpg                     = shadow_invlpg_64,
    .fault                      = shadow_fault_64,
    .update_pagetables          = shadow_update_pagetables,
    .sync_all                   = sync_all,
    .remove_all_write_access    = remove_all_write_access,
    .do_update_va_mapping       = do_update_va_mapping,
    .mark_mfn_out_of_sync       = mark_mfn_out_of_sync,
    .is_out_of_sync             = is_out_of_sync,
    .gva_to_gpa                 = gva_to_gpa_64,
};

#endif
