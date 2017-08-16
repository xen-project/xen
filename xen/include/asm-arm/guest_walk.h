#ifndef _XEN_GUEST_WALK_H
#define _XEN_GUEST_WALK_H

/* Walk the guest's page tables in software. */
int guest_walk_tables(const struct vcpu *v,
                      vaddr_t gva,
                      paddr_t *ipa,
                      unsigned int *perms);

#endif /* _XEN_GUEST_WALK_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
