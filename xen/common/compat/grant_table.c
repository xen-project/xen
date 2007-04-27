/******************************************************************************
 * common/compat/grant_table.c
 *
 */

#include <compat/grant_table.h>

#define xen_grant_entry grant_entry
CHECK_grant_entry;
#undef xen_grant_entry

#define xen_gnttab_map_grant_ref gnttab_map_grant_ref
CHECK_gnttab_map_grant_ref;
#undef xen_gnttab_map_grant_ref

#define xen_gnttab_unmap_grant_ref gnttab_unmap_grant_ref
CHECK_gnttab_unmap_grant_ref;
#undef xen_gnttab_unmap_grant_ref

DEFINE_XEN_GUEST_HANDLE(gnttab_setup_table_compat_t);
DEFINE_XEN_GUEST_HANDLE(gnttab_transfer_compat_t);
DEFINE_XEN_GUEST_HANDLE(gnttab_copy_compat_t);

#define xen_gnttab_dump_table gnttab_dump_table
CHECK_gnttab_dump_table;
#undef xen_gnttab_dump_table

int compat_grant_table_op(unsigned int cmd,
                          XEN_GUEST_HANDLE(void) cmp_uop,
                          unsigned int count)
{
    int rc = 0;
    unsigned int i;

    switch ( cmd )
    {
#define CASE(name) \
    case GNTTABOP_##name: \
        if ( unlikely(!guest_handle_okay(guest_handle_cast(cmp_uop, \
                                                           gnttab_##name##_compat_t), \
                                         count)) ) \
            rc = -EFAULT; \
        break

#ifndef CHECK_gnttab_map_grant_ref
    CASE(map_grant_ref);
#endif

#ifndef CHECK_gnttab_unmap_grant_ref
    CASE(unmap_grant_ref);
#endif

#ifndef CHECK_gnttab_setup_table
    CASE(setup_table);
#endif

#ifndef CHECK_gnttab_transfer
    CASE(transfer);
#endif

#ifndef CHECK_gnttab_copy
    CASE(copy);
#endif

#ifndef CHECK_gnttab_dump_table
    CASE(dump_table);
#endif

#undef CASE
    default:
        return do_grant_table_op(cmd, cmp_uop, count);
    }

    if ( count > 512 )
        rc = -EINVAL;

    for ( i = 0; i < count && rc == 0; )
    {
        unsigned int n;
        union {
            XEN_GUEST_HANDLE(void) uop;
            struct gnttab_setup_table *setup;
            struct gnttab_transfer *xfer;
            struct gnttab_copy *copy;
        } nat;
        union {
            struct compat_gnttab_setup_table setup;
            struct compat_gnttab_transfer xfer;
            struct compat_gnttab_copy copy;
        } cmp;

        set_xen_guest_handle(nat.uop, (void *)COMPAT_ARG_XLAT_VIRT_START(current->vcpu_id));
        switch ( cmd )
        {
        case GNTTABOP_setup_table:
            if ( unlikely(count > 1) )
                rc = -EINVAL;
            else if ( unlikely(__copy_from_guest(&cmp.setup, cmp_uop, 1)) )
                rc = -EFAULT;
            else if ( unlikely(!compat_handle_okay(cmp.setup.frame_list, cmp.setup.nr_frames)) )
                rc = -EFAULT;
            else
            {
                BUG_ON((COMPAT_ARG_XLAT_SIZE - sizeof(*nat.setup)) / sizeof(*nat.setup->frame_list.p) < max_nr_grant_frames);
#define XLAT_gnttab_setup_table_HNDL_frame_list(_d_, _s_) \
                set_xen_guest_handle((_d_)->frame_list, (unsigned long *)(nat.setup + 1))
                XLAT_gnttab_setup_table(nat.setup, &cmp.setup);
#undef XLAT_gnttab_setup_table_HNDL_frame_list
                rc = gnttab_setup_table(guest_handle_cast(nat.uop, gnttab_setup_table_t), 1);
            }
            if ( rc == 0 )
            {
#define XLAT_gnttab_setup_table_HNDL_frame_list(_d_, _s_) \
                do \
                { \
                    if ( (_s_)->status == GNTST_okay ) \
                    { \
                        for ( i = 0; i < (_s_)->nr_frames; ++i ) \
                        { \
                            unsigned int frame = (_s_)->frame_list.p[i]; \
                            BUG_ON(frame != (_s_)->frame_list.p[i]); \
                            (void)__copy_to_compat_offset((_d_)->frame_list, i, &frame, 1); \
                        } \
                    } \
                } while (0)
                XLAT_gnttab_setup_table(&cmp.setup, nat.setup);
#undef XLAT_gnttab_setup_table_HNDL_frame_list
                if ( unlikely(__copy_to_guest(cmp_uop, &cmp.setup, 1)) )
                    rc = -EFAULT;
                else
                    i = 1;
            }
            break;

        case GNTTABOP_transfer:
            for ( n = 0; n < COMPAT_ARG_XLAT_SIZE / sizeof(*nat.xfer) && i < count && rc == 0; ++i, ++n )
            {
                if ( unlikely(__copy_from_guest_offset(&cmp.xfer, cmp_uop, i, 1)) )
                    rc = -EFAULT;
                else
                {
                    XLAT_gnttab_transfer(nat.xfer + n, &cmp.xfer);
                }
            }
            if ( rc == 0 )
                rc = gnttab_transfer(guest_handle_cast(nat.uop, gnttab_transfer_t), n);
            if ( rc == 0 )
            {
                XEN_GUEST_HANDLE(gnttab_transfer_compat_t) xfer;

                xfer = guest_handle_cast(cmp_uop, gnttab_transfer_compat_t);
                guest_handle_add_offset(xfer, i);
                while ( n-- )
                {
                    guest_handle_add_offset(xfer, -1);
                    if ( __copy_field_to_guest(xfer, nat.xfer, status) )
                        rc = -EFAULT;
                }
            }
            break;

        case GNTTABOP_copy:
            for ( n = 0; n < COMPAT_ARG_XLAT_SIZE / sizeof(*nat.copy) && i < count && rc == 0; ++i, ++n )
            {
                if ( unlikely(__copy_from_guest_offset(&cmp.copy, cmp_uop, i, 1)) )
                    rc = -EFAULT;
                else
                {
                    enum XLAT_gnttab_copy_source_u source_u;
                    enum XLAT_gnttab_copy_dest_u dest_u;

                    if ( cmp.copy.flags & GNTCOPY_source_gref )
                        source_u = XLAT_gnttab_copy_source_u_ref;
                    else
                        source_u = XLAT_gnttab_copy_source_u_gmfn;
                    if ( cmp.copy.flags & GNTCOPY_dest_gref )
                        dest_u = XLAT_gnttab_copy_dest_u_ref;
                    else
                        dest_u = XLAT_gnttab_copy_dest_u_gmfn;
                    XLAT_gnttab_copy(nat.copy + n, &cmp.copy);
                }
            }
            if ( rc == 0 )
                rc = gnttab_copy(guest_handle_cast(nat.uop, gnttab_copy_t), n);
            if ( rc == 0 )
            {
                XEN_GUEST_HANDLE(gnttab_copy_compat_t) copy;

                copy = guest_handle_cast(cmp_uop, gnttab_copy_compat_t);
                guest_handle_add_offset(copy, i);
                while ( n-- )
                {
                    guest_handle_add_offset(copy, -1);
                    if ( __copy_field_to_guest(copy, nat.copy, status) )
                        rc = -EFAULT;
                }
            }
            break;

        default:
            domain_crash(current->domain);
            break;
        }
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
