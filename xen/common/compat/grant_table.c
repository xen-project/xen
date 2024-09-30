/******************************************************************************
 * common/compat/grant_table.c
 *
 */

#include <xen/hypercall.h>
#include <compat/grant_table.h>

#define xen_grant_entry_v1 grant_entry_v1
CHECK_grant_entry_v1;
#undef xen_grant_entry_v1

#define xen_grant_entry_header grant_entry_header
CHECK_grant_entry_header;
#undef xen_grant_entry_header

#define xen_grant_entry_v2 grant_entry_v2
CHECK_grant_entry_v2;
#undef xen_grant_entry_v2

#define xen_gnttab_map_grant_ref gnttab_map_grant_ref
CHECK_gnttab_map_grant_ref;
#undef xen_gnttab_map_grant_ref

#define xen_gnttab_unmap_grant_ref gnttab_unmap_grant_ref
CHECK_gnttab_unmap_grant_ref;
#undef xen_gnttab_unmap_grant_ref

#define xen_gnttab_unmap_and_replace gnttab_unmap_and_replace
CHECK_gnttab_unmap_and_replace;
#undef xen_gnttab_unmap_and_replace

#define xen_gnttab_query_size gnttab_query_size
CHECK_gnttab_query_size;
#undef xen_gnttab_query_size

DEFINE_XEN_GUEST_HANDLE(gnttab_setup_table_compat_t);
DEFINE_XEN_GUEST_HANDLE(gnttab_transfer_compat_t);
DEFINE_XEN_GUEST_HANDLE(gnttab_copy_compat_t);

#define xen_gnttab_dump_table gnttab_dump_table
CHECK_gnttab_dump_table;
#undef xen_gnttab_dump_table

#define xen_gnttab_set_version gnttab_set_version
CHECK_gnttab_set_version;
#undef xen_gnttab_set_version

DEFINE_XEN_GUEST_HANDLE(gnttab_get_status_frames_compat_t);

#define xen_gnttab_get_version gnttab_get_version
CHECK_gnttab_get_version;
#undef xen_gnttab_get_version

#define xen_gnttab_swap_grant_ref gnttab_swap_grant_ref
CHECK_gnttab_swap_grant_ref;
#undef xen_gnttab_swap_grant_ref

#define xen_gnttab_cache_flush gnttab_cache_flush
CHECK_gnttab_cache_flush;
#undef xen_gnttab_cache_flush

int compat_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop, unsigned int count)
{
    int rc = 0;
    unsigned int i, cmd_op;
    XEN_GUEST_HANDLE_PARAM(void) cnt_uop;

#ifdef CONFIG_PV_SHIM
    if ( unlikely(pv_shim) )
        return pv_shim_grant_table_op(cmd, uop, count);
#endif

    set_xen_guest_handle(cnt_uop, NULL);
    cmd_op = cmd & GNTTABOP_CMD_MASK;
    if ( cmd_op != GNTTABOP_cache_flush )
        cmd_op = cmd;
    switch ( cmd_op )
    {
#define CASE(name)                                                  \
    case GNTTABOP_ ## name:                                         \
    {                                                               \
        XEN_GUEST_HANDLE_PARAM(gnttab_ ## name ## _compat_t) h =    \
            guest_handle_cast(uop, gnttab_ ## name ## _compat_t);   \
                                                                    \
        if ( unlikely(!guest_handle_okay(h, count)) )               \
            rc = -EFAULT;                                           \
    }                                                               \
        break

#ifndef CHECK_gnttab_map_grant_ref
    CASE(map_grant_ref);
#endif

#ifndef CHECK_gnttab_unmap_grant_ref
    CASE(unmap_grant_ref);
#endif

#ifndef CHECK_gnttab_unmap_and_replace
    CASE(unmap_and_replace);
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

#ifndef CHECK_gnttab_query_size
    CASE(query_size);
#endif

#ifndef CHECK_gnttab_dump_table
    CASE(dump_table);
#endif

#ifndef CHECK_gnttab_get_status_frames
    CASE(get_status_frames);
#endif

#ifndef CHECK_gnttab_swap_grant_ref
    CASE(swap_grant_ref);
#endif

#ifndef CHECK_gnttab_cache_flush
    CASE(cache_flush);
#endif

#undef CASE
    default:
        return do_grant_table_op(cmd, uop, count);
    }

    if ( (int)count < 0 )
        rc = -EINVAL;

    for ( i = 0; i < count && rc == 0; )
    {
        unsigned int n;
        union {
            XEN_GUEST_HANDLE(void) uop;
            struct gnttab_setup_table *setup;
            struct gnttab_transfer *xfer;
            struct gnttab_copy *copy;
            struct gnttab_get_status_frames *get_status;
        } nat;
        union {
            struct compat_gnttab_setup_table setup;
            struct compat_gnttab_transfer xfer;
            struct compat_gnttab_copy copy;
            struct compat_gnttab_get_status_frames get_status;
        } cmp;

        set_xen_guest_handle(nat.uop, COMPAT_ARG_XLAT_VIRT_BASE);
        switch ( cmd_op )
        {
        case GNTTABOP_setup_table:
            if ( unlikely(count > 1) )
                rc = -EINVAL;
            else if ( unlikely(__copy_from_guest(&cmp.setup, uop, 1)) )
                rc = -EFAULT;
            else if ( unlikely(!compat_handle_okay(cmp.setup.frame_list, cmp.setup.nr_frames)) )
                rc = -EFAULT;
            else
            {
                unsigned int max_frame_list_size_in_page =
                    (COMPAT_ARG_XLAT_SIZE - sizeof(*nat.setup)) /
                    sizeof(*nat.setup->frame_list.p);

#define XLAT_gnttab_setup_table_HNDL_frame_list(_d_, _s_) \
                set_xen_guest_handle((_d_)->frame_list, (unsigned long *)(nat.setup + 1))
                XLAT_gnttab_setup_table(nat.setup, &cmp.setup);
#undef XLAT_gnttab_setup_table_HNDL_frame_list
                rc = gnttab_setup_table(guest_handle_cast(nat.uop,
                                                          gnttab_setup_table_t),
                                        1, max_frame_list_size_in_page);
            }
            ASSERT(rc <= 0);
            if ( rc == 0 )
            {
#define XLAT_gnttab_setup_table_HNDL_frame_list(_d_, _s_) \
                do \
                { \
                    if ( (_s_)->status == GNTST_okay ) \
                    { \
                        for ( i = 0; i < (_s_)->nr_frames; ++i ) \
                        { \
                            compat_pfn_t frame = (_s_)->frame_list.p[i]; \
                            if ( frame != (_s_)->frame_list.p[i] ) \
                            { \
                                (_s_)->status = GNTST_address_too_big; \
                                break; \
                            } \
                            if ( __copy_to_compat_offset((_d_)->frame_list, \
                                                         i, &frame, 1) ) \
                            { \
                                (_s_)->status = GNTST_bad_virt_addr; \
                                break; \
                            } \
                        } \
                    } \
                } while (0)
                XLAT_gnttab_setup_table(&cmp.setup, nat.setup);
#undef XLAT_gnttab_setup_table_HNDL_frame_list
                if ( unlikely(__copy_to_guest(uop, &cmp.setup, 1)) )
                    rc = -EFAULT;
                else
                    i = 1;
            }
            break;

        case GNTTABOP_transfer:
            for ( n = 0; n < COMPAT_ARG_XLAT_SIZE / sizeof(*nat.xfer) && i < count && rc == 0; ++i, ++n )
            {
                if ( unlikely(__copy_from_guest_offset(&cmp.xfer, uop, i, 1)) )
                    rc = -EFAULT;
                else
                {
                    XLAT_gnttab_transfer(nat.xfer + n, &cmp.xfer);
                }
            }
            if ( rc == 0 )
                rc = gnttab_transfer(guest_handle_cast(nat.uop, gnttab_transfer_t), n);
            if ( rc > 0 )
            {
                ASSERT(rc < n);
                i -= n - rc;
                n = rc;
            }
            if ( rc >= 0 )
            {
                XEN_GUEST_HANDLE_PARAM(gnttab_transfer_compat_t) xfer;

                xfer = guest_handle_cast(uop, gnttab_transfer_compat_t);
                guest_handle_add_offset(xfer, i);
                cnt_uop = guest_handle_cast(xfer, void);
                while ( n-- )
                {
                    guest_handle_subtract_offset(xfer, 1);
                    if ( __copy_field_to_guest(xfer, nat.xfer + n, status) )
                        rc = -EFAULT;
                }
            }
            break;

        case GNTTABOP_copy:
            for ( n = 0; n < COMPAT_ARG_XLAT_SIZE / sizeof(*nat.copy) && i < count && rc == 0; ++i, ++n )
            {
                if ( unlikely(__copy_from_guest_offset(&cmp.copy, uop, i, 1)) )
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
            if ( rc > 0 )
            {
                ASSERT(rc <= n);
                i -= rc;
                n -= rc;
            }
            if ( rc >= 0 )
            {
                XEN_GUEST_HANDLE_PARAM(gnttab_copy_compat_t) copy;

                copy = guest_handle_cast(uop, gnttab_copy_compat_t);
                guest_handle_add_offset(copy, i);
                cnt_uop = guest_handle_cast(copy, void);
                while ( n-- )
                {
                    guest_handle_subtract_offset(copy, 1);
                    if ( __copy_field_to_guest(copy, nat.copy + n, status) )
                        rc = -EFAULT;
                }
            }
            break;

        case GNTTABOP_get_status_frames:
            if ( count != 1)
            {
                rc = -EINVAL;
                break;
            }
            if ( unlikely(__copy_from_guest(&cmp.get_status, uop, 1) ||
                          !compat_handle_okay(cmp.get_status.frame_list,
                                              cmp.get_status.nr_frames)) )
            {
                rc = -EFAULT;
                break;
            }

#define XLAT_gnttab_get_status_frames_HNDL_frame_list(_d_, _s_) \
            guest_from_compat_handle((_d_)->frame_list, (_s_)->frame_list)
            XLAT_gnttab_get_status_frames(nat.get_status, &cmp.get_status);
#undef XLAT_gnttab_get_status_frames_HNDL_frame_list

            rc = gnttab_get_status_frames(
                guest_handle_cast(nat.uop, gnttab_get_status_frames_t), count);
            if ( rc >= 0 )
            {
                XEN_GUEST_HANDLE_PARAM(gnttab_get_status_frames_compat_t) get =
                    guest_handle_cast(uop,
                                      gnttab_get_status_frames_compat_t);

                if ( unlikely(__copy_field_to_guest(get, nat.get_status,
                                                    status)) )
                    rc = -EFAULT;
                else
                    i = 1;
            }
            break;

        default:
            domain_crash(current->domain);
            break;
        }
    }

    if ( rc > 0 )
    {
        ASSERT(i < count);
        ASSERT(!guest_handle_is_null(cnt_uop));
        rc = hypercall_create_continuation(__HYPERVISOR_grant_table_op,
                                           "ihi", cmd, cnt_uop, count - i);
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
