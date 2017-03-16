DMOP
====

Introduction
------------

The aim of DMOP is to prevent a compromised device model from compromising
domains other than the one it is providing emulation for (which is therefore
likely already compromised).

The problem occurs when you a device model issues an hypercall that
includes references to user memory other than the operation structure
itself, such as with Track dirty VRAM (as used in VGA emulation).
Is this case, the address of this other user memory needs to be vetted,
to ensure it is not within restricted address ranges, such as kernel
memory. The real problem comes down to how you would vet this address -
the idea place to do this is within the privcmd driver, without privcmd
having to have specific knowledge of the hypercall's semantics.

The Design
----------

The privcmd driver implements a new restriction ioctl, which takes a domid
parameter.  After that restriction ioctl is issued, all unaudited operations
on the privcmd driver will cease to function, including regular hypercalls.
DMOP hypercalls will continue to function as they can be audited.

A DMOP hypercall consists of a domid (which is audited to verify that it
matches any restriction in place) and an array of buffers and lengths,
with the first one containing the specific DMOP parameters. These can
then reference further buffers from within in the array. Since the only
user buffers passed are that found with that array, they can all can be
audited by privcmd.

The following code illustrates this idea:

struct xen_dm_op {
    uint32_t op;
};

struct xen_dm_op_buf {
    XEN_GUEST_HANDLE(void) h;
    unsigned long size;
};
typedef struct xen_dm_op_buf xen_dm_op_buf_t;

enum neg_errnoval
HYPERVISOR_dm_op(domid_t domid,
                 xen_dm_op_buf_t bufs[],
                 unsigned int nr_bufs)

@domid is the domain the hypercall operates on.
@bufs points to an array of buffers where @bufs[0] contains a struct
dm_op, describing the specific device model operation and its parameters.
@bufs[1..] may be referenced in the parameters for the purposes of
passing extra information to or from the domain.
@nr_bufs is the number of buffers in the @bufs array.

It is forbidden for the above struct (xen_dm_op) to contain any guest
handles. If they are needed, they should instead be in
HYPERVISOR_dm_op->bufs.

Validation by privcmd driver
----------------------------

If the privcmd driver has been restricted to specific domain (using a
 new ioctl), when it received an op, it will:

1. Check hypercall is DMOP.

2. Check domid == restricted domid.

3. For each @nr_bufs in @bufs: Check @h and @size give a buffer
   wholly in the user space part of the virtual address space. (e.g.
   Linux will use access_ok()).


Xen Implementation
------------------

Since a DMOP buffers need to be copied from or to the guest, functions for
doing this would be written as below.  Note that care is taken to prevent
damage from buffer under- or over-run situations.  If the DMOP is called
with incorrectly sized buffers, zeros will be read, while extra is ignored.

static bool copy_buf_from_guest(xen_dm_op_buf_t bufs[],
                                unsigned int nr_bufs, void *dst,
                                unsigned int idx, size_t dst_size)
{
    size_t size;

    if ( idx >= nr_bufs )
        return false;

    memset(dst, 0, dst_size);

    size = min_t(size_t, dst_size, bufs[idx].size);

    return !copy_from_guest(dst, bufs[idx].h, size);
}

static bool copy_buf_to_guest(xen_dm_op_buf_t bufs[],
                              unsigned int nr_bufs, unsigned int idx,
                              void *src, size_t src_size)
{
    size_t size;

    if ( idx >= nr_bufs )
        return false;

    size = min_t(size_t, bufs[idx].size, src_size);

    return !copy_to_guest(bufs[idx].h, src, size);
}

This leaves do_dm_op easy to implement as below:

static int dm_op(domid_t domid,
                 unsigned int nr_bufs,
                 xen_dm_op_buf_t bufs[])
{
    struct domain *d;
    struct xen_dm_op op;
    bool const_op = true;
    long rc;

    rc = rcu_lock_remote_domain_by_id(domid, &d);
    if ( rc )
        return rc;

    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_dm_op(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    if ( !copy_buf_from_guest(bufs, nr_bufs, &op, 0, sizeof(op)) )
    {
        rc = -EFAULT;
        goto out;
    }

    switch ( op.op )
    {
    default:
        rc = -EOPNOTSUPP;
        break;
    }

    if ( !rc &&
         !const_op &&
         !copy_buf_to_guest(bufs, nr_bufs, 0, &op, sizeof(op)) )
        rc = -EFAULT;

 out:
    rcu_unlock_domain(d);

    return rc;
}

long do_dm_op(domid_t domid,
              unsigned int nr_bufs,
              XEN_GUEST_HANDLE_PARAM(xen_dm_op_buf_t) bufs)
{
    struct xen_dm_op_buf nat[MAX_NR_BUFS];

    if ( nr_bufs > MAX_NR_BUFS )
        return -EINVAL;

    if ( copy_from_guest_offset(nat, bufs, 0, nr_bufs) )
        return -EFAULT;

    return dm_op(domid, nr_bufs, nat);
}
