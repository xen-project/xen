/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <xen/vmap.h>
#include <xen/xsplice.h>

#include <asm/event.h>
#include <public/sysctl.h>

/* Protects against payload_list operations. */
static DEFINE_SPINLOCK(payload_lock);
static LIST_HEAD(payload_list);

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

struct payload {
    uint32_t state;                      /* One of the XSPLICE_STATE_*. */
    int32_t rc;                          /* 0 or -XEN_EXX. */
    struct list_head list;               /* Linked to 'payload_list'. */
    char name[XEN_XSPLICE_NAME_SIZE];    /* Name of it. */
};

static int get_name(const xen_xsplice_name_t *name, char *n)
{
    if ( !name->size || name->size > XEN_XSPLICE_NAME_SIZE )
        return -EINVAL;

    if ( name->pad[0] || name->pad[1] || name->pad[2] )
        return -EINVAL;

    if ( copy_from_guest(n, name->name, name->size) )
        return -EFAULT;

    if ( n[name->size - 1] )
        return -EINVAL;

    return 0;
}

static int verify_payload(const xen_sysctl_xsplice_upload_t *upload, char *n)
{
    if ( get_name(&upload->name, n) )
        return -EINVAL;

    if ( !upload->size )
        return -EINVAL;

    if ( upload->size > MB(2) )
        return -EINVAL;

    if ( !guest_handle_okay(upload->payload, upload->size) )
        return -EFAULT;

    return 0;
}

static struct payload *find_payload(const char *name)
{
    struct payload *data, *found = NULL;

    ASSERT(spin_is_locked(&payload_lock));
    list_for_each_entry ( data, &payload_list, list )
    {
        if ( !strcmp(data->name, name) )
        {
            found = data;
            break;
        }
    }

    return found;
}

static void free_payload(struct payload *data)
{
    ASSERT(spin_is_locked(&payload_lock));
    list_del(&data->list);
    payload_cnt--;
    payload_version++;
    xfree(data);
}

static int xsplice_upload(xen_sysctl_xsplice_upload_t *upload)
{
    struct payload *data, *found;
    char n[XEN_XSPLICE_NAME_SIZE];
    int rc;

    rc = verify_payload(upload, n);
    if ( rc )
        return rc;

    data = xzalloc(struct payload);

    spin_lock(&payload_lock);

    found = find_payload(n);
    if ( IS_ERR(found) )
        rc = PTR_ERR(found);
    else if ( found )
        rc = -EEXIST;
    else if ( !data )
        rc = -ENOMEM;
    else
    {
        memcpy(data->name, n, strlen(n));
        data->state = XSPLICE_STATE_CHECKED;
        INIT_LIST_HEAD(&data->list);

        list_add_tail(&data->list, &payload_list);
        payload_cnt++;
        payload_version++;
    }
    spin_unlock(&payload_lock);

    if ( rc )
        xfree(data);

    return rc;
}

static int xsplice_get(xen_sysctl_xsplice_get_t *get)
{
    struct payload *data;
    int rc;
    char n[XEN_XSPLICE_NAME_SIZE];

    rc = get_name(&get->name, n);
    if ( rc )
        return rc;

    spin_lock(&payload_lock);

    data = find_payload(n);
    if ( IS_ERR_OR_NULL(data) )
    {
        spin_unlock(&payload_lock);

        if ( !data )
            return -ENOENT;

        return PTR_ERR(data);
    }

    get->status.state = data->state;
    get->status.rc = data->rc;

    spin_unlock(&payload_lock);

    return 0;
}

static int xsplice_list(xen_sysctl_xsplice_list_t *list)
{
    xen_xsplice_status_t status;
    struct payload *data;
    unsigned int idx = 0, i = 0;
    int rc = 0;

    if ( list->nr > 1024 )
        return -E2BIG;

    if ( list->pad )
        return -EINVAL;

    if ( list->nr &&
         (!guest_handle_okay(list->status, list->nr) ||
          !guest_handle_okay(list->name, XEN_XSPLICE_NAME_SIZE * list->nr) ||
          !guest_handle_okay(list->len, list->nr)) )
        return -EINVAL;

    spin_lock(&payload_lock);
    if ( list->idx >= payload_cnt && payload_cnt )
    {
        spin_unlock(&payload_lock);
        return -EINVAL;
    }

    if ( list->nr )
    {
        list_for_each_entry( data, &payload_list, list )
        {
            uint32_t len;

            if ( list->idx > i++ )
                continue;

            status.state = data->state;
            status.rc = data->rc;
            len = strlen(data->name) + 1;

            /* N.B. 'idx' != 'i'. */
            if ( __copy_to_guest_offset(list->name, idx * XEN_XSPLICE_NAME_SIZE,
                                        data->name, len) ||
                __copy_to_guest_offset(list->len, idx, &len, 1) ||
                __copy_to_guest_offset(list->status, idx, &status, 1) )
            {
                rc = -EFAULT;
                break;
            }

            idx++;

            if ( (idx >= list->nr) || hypercall_preempt_check() )
                break;
        }
    }
    list->nr = payload_cnt - i; /* Remaining amount. */
    list->version = payload_version;
    spin_unlock(&payload_lock);

    /* And how many we have processed. */
    return rc ? : idx;
}

static int xsplice_action(xen_sysctl_xsplice_action_t *action)
{
    struct payload *data;
    char n[XEN_XSPLICE_NAME_SIZE];
    int rc;

    rc = get_name(&action->name, n);
    if ( rc )
        return rc;

    spin_lock(&payload_lock);

    data = find_payload(n);
    if ( IS_ERR_OR_NULL(data) )
    {
        spin_unlock(&payload_lock);

        if ( !data )
            return -ENOENT;

        return PTR_ERR(data);
    }

    switch ( action->cmd )
    {
    case XSPLICE_ACTION_UNLOAD:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            free_payload(data);
            /* No touching 'data' from here on! */
            data = NULL;
        }
        else
            rc = -EINVAL;
        break;

    case XSPLICE_ACTION_REVERT:
        if ( data->state == XSPLICE_STATE_APPLIED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
        }
        break;

    case XSPLICE_ACTION_APPLY:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_APPLIED;
            data->rc = 0;
        }
        break;

    case XSPLICE_ACTION_REPLACE:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
        }
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
    }

    spin_unlock(&payload_lock);

    return rc;
}

int xsplice_op(xen_sysctl_xsplice_op_t *xsplice)
{
    int rc;

    if ( xsplice->pad )
        return -EINVAL;

    switch ( xsplice->cmd )
    {
    case XEN_SYSCTL_XSPLICE_UPLOAD:
        rc = xsplice_upload(&xsplice->u.upload);
        break;

    case XEN_SYSCTL_XSPLICE_GET:
        rc = xsplice_get(&xsplice->u.get);
        break;

    case XEN_SYSCTL_XSPLICE_LIST:
        rc = xsplice_list(&xsplice->u.list);
        break;

    case XEN_SYSCTL_XSPLICE_ACTION:
        rc = xsplice_action(&xsplice->u.action);
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
   }

    return rc;
}

static const char *state2str(unsigned int state)
{
#define STATE(x) [XSPLICE_STATE_##x] = #x
    static const char *const names[] = {
            STATE(CHECKED),
            STATE(APPLIED),
    };
#undef STATE

    if ( state >= ARRAY_SIZE(names) || !names[state] )
        return "unknown";

    return names[state];
}

static void xsplice_printall(unsigned char key)
{
    struct payload *data;

    printk("'%c' pressed - Dumping all xsplice patches\n", key);

    if ( !spin_trylock(&payload_lock) )
    {
        printk("Lock held. Try again.\n");
        return;
    }

    list_for_each_entry ( data, &payload_list, list )
        printk(" name=%s state=%s(%d)\n", data->name,
               state2str(data->state), data->state);

    spin_unlock(&payload_lock);
}

static int __init xsplice_init(void)
{
    register_keyhandler('x', xsplice_printall, "print xsplicing info", 1);
    return 0;
}
__initcall(xsplice_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
