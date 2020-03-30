/******************************************************************************
 * xc_misc.c
 *
 * Miscellaneous control interface functions.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_bitops.h"
#include "xc_private.h"
#include <xen/hvm/hvm_op.h>

int xc_get_max_cpus(xc_interface *xch)
{
    static int max_cpus = 0;
    xc_physinfo_t physinfo;

    if ( max_cpus )
        return max_cpus;

    if ( !xc_physinfo(xch, &physinfo) )
    {
        max_cpus = physinfo.max_cpu_id + 1;
        return max_cpus;
    }

    return -1;
}

int xc_get_online_cpus(xc_interface *xch)
{
    xc_physinfo_t physinfo;

    if ( !xc_physinfo(xch, &physinfo) )
        return physinfo.nr_cpus;

    return -1;
}

int xc_get_max_nodes(xc_interface *xch)
{
    static int max_nodes = 0;
    xc_physinfo_t physinfo;

    if ( max_nodes )
        return max_nodes;

    if ( !xc_physinfo(xch, &physinfo) )
    {
        max_nodes = physinfo.max_node_id + 1;
        return max_nodes;
    }

    return -1;
}

int xc_get_cpumap_size(xc_interface *xch)
{
    int max_cpus = xc_get_max_cpus(xch);

    if ( max_cpus < 0 )
        return -1;
    return (max_cpus + 7) / 8;
}

int xc_get_nodemap_size(xc_interface *xch)
{
    int max_nodes = xc_get_max_nodes(xch);

    if ( max_nodes < 0 )
        return -1;
    return (max_nodes + 7) / 8;
}

xc_cpumap_t xc_cpumap_alloc(xc_interface *xch)
{
    int sz;

    sz = xc_get_cpumap_size(xch);
    if (sz <= 0)
        return NULL;
    return calloc(1, sz);
}

/*
 * xc_bitops.h has macros that do this as well - however they assume that
 * the bitmask is word aligned but xc_cpumap_t is only guaranteed to be
 * byte aligned and so we need byte versions for architectures which do
 * not support misaligned accesses (which is basically everyone
 * but x86, although even on x86 it can be inefficient).
 *
 * NOTE: The xc_bitops macros now use byte alignment.
 * TODO: Clean up the users of this interface.
 */
#define BITS_PER_CPUMAP(map) (sizeof(*map) * 8)
#define CPUMAP_ENTRY(cpu, map) ((map))[(cpu) / BITS_PER_CPUMAP(map)]
#define CPUMAP_SHIFT(cpu, map) ((cpu) % BITS_PER_CPUMAP(map))
void xc_cpumap_clearcpu(int cpu, xc_cpumap_t map)
{
    CPUMAP_ENTRY(cpu, map) &= ~(1U << CPUMAP_SHIFT(cpu, map));
}

void xc_cpumap_setcpu(int cpu, xc_cpumap_t map)
{
    CPUMAP_ENTRY(cpu, map) |= (1U << CPUMAP_SHIFT(cpu, map));
}

int xc_cpumap_testcpu(int cpu, xc_cpumap_t map)
{
    return (CPUMAP_ENTRY(cpu, map) >> CPUMAP_SHIFT(cpu, map)) & 1;
}

xc_nodemap_t xc_nodemap_alloc(xc_interface *xch)
{
    int sz;

    sz = xc_get_nodemap_size(xch);
    if (sz <= 0)
        return NULL;
    return calloc(1, sz);
}

int xc_readconsolering(xc_interface *xch,
                       char *buffer,
                       unsigned int *pnr_chars,
                       int clear, int incremental, uint32_t *pindex)
{
    int ret;
    unsigned int nr_chars = *pnr_chars;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(buffer, nr_chars, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, buffer) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_readconsole;
    set_xen_guest_handle(sysctl.u.readconsole.buffer, buffer);
    sysctl.u.readconsole.count = nr_chars;
    sysctl.u.readconsole.clear = clear;
    sysctl.u.readconsole.incremental = 0;
    if ( pindex )
    {
        sysctl.u.readconsole.index = *pindex;
        sysctl.u.readconsole.incremental = incremental;
    }

    if ( (ret = do_sysctl(xch, &sysctl)) == 0 )
    {
        *pnr_chars = sysctl.u.readconsole.count;
        if ( pindex )
            *pindex = sysctl.u.readconsole.index;
    }

    xc_hypercall_bounce_post(xch, buffer);

    return ret;
}

int xc_send_debug_keys(xc_interface *xch, const char *keys)
{
    int ret, len = strlen(keys);
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE_IN(keys, len);

    if ( xc_hypercall_bounce_pre(xch, keys) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_debug_keys;
    set_xen_guest_handle(sysctl.u.debug_keys.keys, keys);
    sysctl.u.debug_keys.nr_keys = len;

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, keys);

    return ret;
}

int xc_set_parameters(xc_interface *xch, const char *params)
{
    int ret, len = strlen(params);
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE_IN(params, len);

    if ( xc_hypercall_bounce_pre(xch, params) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_set_parameter;
    set_xen_guest_handle(sysctl.u.set_parameter.params, params);
    sysctl.u.set_parameter.size = len;
    memset(sysctl.u.set_parameter.pad, 0, sizeof(sysctl.u.set_parameter.pad));

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, params);

    return ret;
}

int xc_physinfo(xc_interface *xch,
                xc_physinfo_t *put_info)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_physinfo;

    memcpy(&sysctl.u.physinfo, put_info, sizeof(*put_info));

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        return ret;

    memcpy(put_info, &sysctl.u.physinfo, sizeof(*put_info));

    return 0;
}

int xc_microcode_update(xc_interface *xch, const void *buf, size_t len)
{
    int ret;
    DECLARE_PLATFORM_OP;
    DECLARE_HYPERCALL_BUFFER(struct xenpf_microcode_update, uc);

    uc = xc_hypercall_buffer_alloc(xch, uc, len);
    if ( uc == NULL )
        return -1;

    memcpy(uc, buf, len);

    platform_op.cmd = XENPF_microcode_update;
    platform_op.u.microcode.length = len;
    set_xen_guest_handle(platform_op.u.microcode.data, uc);

    ret = do_platform_op(xch, &platform_op);

    xc_hypercall_buffer_free(xch, uc);

    return ret;
}

int xc_cputopoinfo(xc_interface *xch, unsigned *max_cpus,
                   xc_cputopo_t *cputopo)
{
    int ret;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(cputopo, *max_cpus * sizeof(*cputopo),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( (ret = xc_hypercall_bounce_pre(xch, cputopo)) )
        goto out;

    sysctl.u.cputopoinfo.num_cpus = *max_cpus;
    set_xen_guest_handle(sysctl.u.cputopoinfo.cputopo, cputopo);

    sysctl.cmd = XEN_SYSCTL_cputopoinfo;

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        goto out;

    *max_cpus = sysctl.u.cputopoinfo.num_cpus;

out:
    xc_hypercall_bounce_post(xch, cputopo);

    return ret;
}

int xc_numainfo(xc_interface *xch, unsigned *max_nodes,
                xc_meminfo_t *meminfo, uint32_t *distance)
{
    int ret;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(meminfo, *max_nodes * sizeof(*meminfo),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(distance,
                             *max_nodes * *max_nodes * sizeof(*distance),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( (ret = xc_hypercall_bounce_pre(xch, meminfo)) )
        goto out;
    if ((ret = xc_hypercall_bounce_pre(xch, distance)) )
        goto out;

    sysctl.u.numainfo.num_nodes = *max_nodes;
    set_xen_guest_handle(sysctl.u.numainfo.meminfo, meminfo);
    set_xen_guest_handle(sysctl.u.numainfo.distance, distance);

    sysctl.cmd = XEN_SYSCTL_numainfo;

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        goto out;

    *max_nodes = sysctl.u.numainfo.num_nodes;

out:
    xc_hypercall_bounce_post(xch, meminfo);
    xc_hypercall_bounce_post(xch, distance);

    return ret;
}

int xc_pcitopoinfo(xc_interface *xch, unsigned num_devs,
                   physdev_pci_device_t *devs,
                   uint32_t *nodes)
{
    int ret = 0;
    unsigned processed = 0;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(devs, num_devs * sizeof(*devs),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(nodes, num_devs* sizeof(*nodes),
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( (ret = xc_hypercall_bounce_pre(xch, devs)) )
        goto out;
    if ( (ret = xc_hypercall_bounce_pre(xch, nodes)) )
        goto out;

    sysctl.cmd = XEN_SYSCTL_pcitopoinfo;

    while ( processed < num_devs )
    {
        sysctl.u.pcitopoinfo.num_devs = num_devs - processed;
        set_xen_guest_handle_offset(sysctl.u.pcitopoinfo.devs, devs,
                                    processed);
        set_xen_guest_handle_offset(sysctl.u.pcitopoinfo.nodes, nodes,
                                    processed);

        if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
                break;

        processed += sysctl.u.pcitopoinfo.num_devs;
    }

 out:
    xc_hypercall_bounce_post(xch, devs);
    xc_hypercall_bounce_post(xch, nodes);

    return ret;
}

int xc_sched_id(xc_interface *xch,
                int *sched_id)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_sched_id;

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        return ret;

    *sched_id = sysctl.u.sched_id.sched_id;

    return 0;
}

#if defined(__i386__) || defined(__x86_64__)
int xc_mca_op(xc_interface *xch, struct xen_mc *mc)
{
    int ret = 0;
    DECLARE_HYPERCALL_BOUNCE(mc, sizeof(*mc), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, mc) )
    {
        PERROR("Could not bounce xen_mc memory buffer");
        return -1;
    }
    mc->interface_version = XEN_MCA_INTERFACE_VERSION;

    ret = xencall1(xch->xcall, __HYPERVISOR_mca,
                   HYPERCALL_BUFFER_AS_ARG(mc));

    xc_hypercall_bounce_post(xch, mc);
    return ret;
}

int xc_mca_op_inject_v2(xc_interface *xch, unsigned int flags,
                        xc_cpumap_t cpumap, unsigned int nr_bits)
{
    int ret = -1;
    struct xen_mc mc_buf, *mc = &mc_buf;
    struct xen_mc_inject_v2 *inject = &mc->u.mc_inject_v2;

    DECLARE_HYPERCALL_BOUNCE(cpumap, 0, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(mc, sizeof(*mc), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    memset(mc, 0, sizeof(*mc));

    if ( cpumap )
    {
        if ( !nr_bits )
        {
            errno = EINVAL;
            goto out;
        }

        HYPERCALL_BOUNCE_SET_SIZE(cpumap, (nr_bits + 7) / 8);
        if ( xc_hypercall_bounce_pre(xch, cpumap) )
        {
            PERROR("Could not bounce cpumap memory buffer");
            goto out;
        }
        set_xen_guest_handle(inject->cpumap.bitmap, cpumap);
        inject->cpumap.nr_bits = nr_bits;
    }

    inject->flags = flags;
    mc->cmd = XEN_MC_inject_v2;
    mc->interface_version = XEN_MCA_INTERFACE_VERSION;

    if ( xc_hypercall_bounce_pre(xch, mc) )
    {
        PERROR("Could not bounce xen_mc memory buffer");
        goto out_free_cpumap;
    }

    ret = xencall1(xch->xcall, __HYPERVISOR_mca, HYPERCALL_BUFFER_AS_ARG(mc));

    xc_hypercall_bounce_post(xch, mc);
out_free_cpumap:
    if ( cpumap )
        xc_hypercall_bounce_post(xch, cpumap);
out:
    return ret;
}
#endif /* __i386__ || __x86_64__ */

int xc_perfc_reset(xc_interface *xch)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_reset;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, HYPERCALL_BUFFER_NULL);
    set_xen_guest_handle(sysctl.u.perfc_op.val, HYPERCALL_BUFFER_NULL);

    return do_sysctl(xch, &sysctl);
}

int xc_perfc_query_number(xc_interface *xch,
                          int *nbr_desc,
                          int *nbr_val)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_query;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, HYPERCALL_BUFFER_NULL);
    set_xen_guest_handle(sysctl.u.perfc_op.val, HYPERCALL_BUFFER_NULL);

    rc = do_sysctl(xch, &sysctl);

    if ( nbr_desc )
        *nbr_desc = sysctl.u.perfc_op.nr_counters;
    if ( nbr_val )
        *nbr_val = sysctl.u.perfc_op.nr_vals;

    return rc;
}

int xc_perfc_query(xc_interface *xch,
                   struct xc_hypercall_buffer *desc,
                   struct xc_hypercall_buffer *val)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(desc);
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(val);

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_query;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, desc);
    set_xen_guest_handle(sysctl.u.perfc_op.val, val);

    return do_sysctl(xch, &sysctl);
}

int xc_lockprof_reset(xc_interface *xch)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_lockprof_op;
    sysctl.u.lockprof_op.cmd = XEN_SYSCTL_LOCKPROF_reset;
    set_xen_guest_handle(sysctl.u.lockprof_op.data, HYPERCALL_BUFFER_NULL);

    return do_sysctl(xch, &sysctl);
}

int xc_lockprof_query_number(xc_interface *xch,
                             uint32_t *n_elems)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_lockprof_op;
    sysctl.u.lockprof_op.max_elem = 0;
    sysctl.u.lockprof_op.cmd = XEN_SYSCTL_LOCKPROF_query;
    set_xen_guest_handle(sysctl.u.lockprof_op.data, HYPERCALL_BUFFER_NULL);

    rc = do_sysctl(xch, &sysctl);

    *n_elems = sysctl.u.lockprof_op.nr_elem;

    return rc;
}

int xc_lockprof_query(xc_interface *xch,
                      uint32_t *n_elems,
                      uint64_t *time,
                      struct xc_hypercall_buffer *data)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(data);

    sysctl.cmd = XEN_SYSCTL_lockprof_op;
    sysctl.u.lockprof_op.cmd = XEN_SYSCTL_LOCKPROF_query;
    sysctl.u.lockprof_op.max_elem = *n_elems;
    set_xen_guest_handle(sysctl.u.lockprof_op.data, data);

    rc = do_sysctl(xch, &sysctl);

    *n_elems = sysctl.u.lockprof_op.nr_elem;

    return rc;
}

int xc_getcpuinfo(xc_interface *xch, int max_cpus,
                  xc_cpuinfo_t *info, int *nr_cpus)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(info, max_cpus*sizeof(*info), XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, info) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_getcpuinfo;
    sysctl.u.getcpuinfo.max_cpus = max_cpus;
    set_xen_guest_handle(sysctl.u.getcpuinfo.info, info);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, info);

    if ( nr_cpus )
        *nr_cpus = sysctl.u.getcpuinfo.nr_cpus;

    return rc;
}

int xc_livepatch_upload(xc_interface *xch,
                        char *name,
                        unsigned char *payload,
                        uint32_t size)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER(char, local);
    DECLARE_HYPERCALL_BOUNCE(name, 0 /* later */, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    struct xen_livepatch_name def_name = { };

    if ( !name || !payload )
    {
        errno = EINVAL;
        return -1;
    }

    def_name.size = strlen(name) + 1;
    if ( def_name.size > XEN_LIVEPATCH_NAME_SIZE )
    {
        errno = EINVAL;
        return -1;
    }

    HYPERCALL_BOUNCE_SET_SIZE(name, def_name.size);

    if ( xc_hypercall_bounce_pre(xch, name) )
        return -1;

    local = xc_hypercall_buffer_alloc(xch, local, size);
    if ( !local )
    {
        xc_hypercall_bounce_post(xch, name);
        return -1;
    }
    memcpy(local, payload, size);

    sysctl.cmd = XEN_SYSCTL_livepatch_op;
    sysctl.u.livepatch.cmd = XEN_SYSCTL_LIVEPATCH_UPLOAD;
    sysctl.u.livepatch.pad = 0;
    sysctl.u.livepatch.u.upload.size = size;
    set_xen_guest_handle(sysctl.u.livepatch.u.upload.payload, local);

    sysctl.u.livepatch.u.upload.name = def_name;
    set_xen_guest_handle(sysctl.u.livepatch.u.upload.name.name, name);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_buffer_free(xch, local);
    xc_hypercall_bounce_post(xch, name);

    return rc;
}

int xc_livepatch_get(xc_interface *xch,
                     char *name,
                     struct xen_livepatch_status *status)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(name, 0 /*adjust later */, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    struct xen_livepatch_name def_name = { };

    if ( !name )
    {
        errno = EINVAL;
        return -1;
    }

    def_name.size = strlen(name) + 1;
    if ( def_name.size > XEN_LIVEPATCH_NAME_SIZE )
    {
        errno = EINVAL;
        return -1;
    }

    HYPERCALL_BOUNCE_SET_SIZE(name, def_name.size);

    if ( xc_hypercall_bounce_pre(xch, name) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_livepatch_op;
    sysctl.u.livepatch.cmd = XEN_SYSCTL_LIVEPATCH_GET;
    sysctl.u.livepatch.pad = 0;

    sysctl.u.livepatch.u.get.status.state = 0;
    sysctl.u.livepatch.u.get.status.rc = 0;

    sysctl.u.livepatch.u.get.name = def_name;
    set_xen_guest_handle(sysctl.u.livepatch.u.get.name.name, name);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, name);

    memcpy(status, &sysctl.u.livepatch.u.get.status, sizeof(*status));

    return rc;
}

/*
 * Get a number of available payloads and get actual total size of
 * the payloads' name and metadata arrays.
 *
 * This functions is typically executed first before the xc_livepatch_list()
 * to obtain the sizes and correctly allocate all necessary data resources.
 *
 * The return value is zero if the hypercall completed successfully.
 *
 * If there was an error performing the sysctl operation, the return value
 * will contain the hypercall error code value.
 */
int xc_livepatch_list_get_sizes(xc_interface *xch, unsigned int *nr,
                                uint32_t *name_total_size,
                                uint32_t *metadata_total_size)
{
    DECLARE_SYSCTL;
    int rc;

    if ( !nr || !name_total_size || !metadata_total_size )
    {
        errno = EINVAL;
        return -1;
    }

    memset(&sysctl, 0, sizeof(sysctl));
    sysctl.cmd = XEN_SYSCTL_livepatch_op;
    sysctl.u.livepatch.cmd = XEN_SYSCTL_LIVEPATCH_LIST;

    rc = do_sysctl(xch, &sysctl);
    if ( rc )
        return rc;

    *nr = sysctl.u.livepatch.u.list.nr;
    *name_total_size = sysctl.u.livepatch.u.list.name_total_size;
    *metadata_total_size = sysctl.u.livepatch.u.list.metadata_total_size;

    return 0;
}

/*
 * The heart of this function is to get an array of the following objects:
 *   - xen_livepatch_status_t: states and return codes of payloads
 *   - name: names of payloads
 *   - len: lengths of corresponding payloads' names
 *   - metadata: payloads' metadata
 *   - metadata_len: lengths of corresponding payloads' metadata
 *
 * However it is complex because it has to deal with the hypervisor
 * returning some of the requested data or data being stale
 * (another hypercall might alter the list).
 *
 * The parameters that the function expects to contain data from
 * the hypervisor are: 'info', 'name', and 'len'. The 'done' and
 * 'left' are also updated with the number of entries filled out
 * and respectively the number of entries left to get from hypervisor.
 *
 * It is expected that the caller of this function will first issue the
 * xc_livepatch_list_get_sizes() in order to obtain total sizes of names
 * and all metadata as well as the current number of payload entries.
 * The total sizes are required and supplied via the 'name_total_size' and
 * 'metadata_total_size' parameters.
 *
 * The 'max' is to be provided by the caller with the maximum number of
 * entries that 'info', 'name', 'len', 'metadata' and 'metadata_len' arrays
 * can be filled up with.
 *
 * Each entry in the 'info' array is expected to be of xen_livepatch_status_t
 * structure size.
 *
 * Each entry in the 'name' array may have an arbitrary size.
 *
 * Each entry in the 'len' array is expected to be of uint32_t size.
 *
 * Each entry in the 'metadata' array may have an arbitrary size.
 *
 * Each entry in the 'metadata_len' array is expected to be of uint32_t size.
 *
 * The return value is zero if the hypercall completed successfully.
 * Note that the return value is _not_ the amount of entries filled
 * out - that is saved in 'done'.
 *
 * If there was an error performing the operation, the return value
 * will contain an negative -EXX type value. The 'done' and 'left'
 * will contain the number of entries that had been succesfully
 * retrieved (if any).
 */
int xc_livepatch_list(xc_interface *xch, const unsigned int max,
                      const unsigned int start,
                      struct xen_livepatch_status *info,
                      char *name, uint32_t *len,
                      const uint32_t name_total_size,
                      char *metadata, uint32_t *metadata_len,
                      const uint32_t metadata_total_size,
                      unsigned int *done, unsigned int *left)
{
    int rc;
    DECLARE_SYSCTL;
    /* The sizes are adjusted later - hence zero. */
    DECLARE_HYPERCALL_BOUNCE(info, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(name, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(len, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(metadata, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(metadata_len, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    uint32_t max_batch_sz, nr;
    uint32_t version = 0, retries = 0;
    uint32_t adjust = 0;
    uint32_t name_off = 0, metadata_off = 0;
    uint32_t name_sz, metadata_sz;

    if ( !max || !info || !name || !len ||
         !metadata || !metadata_len || !done || !left )
    {
        errno = EINVAL;
        return -1;
    }

    if ( name_total_size == 0 )
    {
        errno = ENOENT;
        return -1;
    }

    memset(&sysctl, 0, sizeof(sysctl));
    sysctl.cmd = XEN_SYSCTL_livepatch_op;
    sysctl.u.livepatch.cmd = XEN_SYSCTL_LIVEPATCH_LIST;
    sysctl.u.livepatch.u.list.idx = start;

    max_batch_sz = max;
    name_sz = name_total_size;
    metadata_sz = metadata_total_size;
    *done = 0;
    *left = 0;
    do {
        uint32_t _name_sz, _metadata_sz;

        /*
         * The first time we go in this loop our 'max' may be bigger
         * than what the hypervisor is comfortable with - hence the first
         * couple of loops may adjust the number of entries we will
         * want filled (tracked by 'nr').
         *
         * N.B. This is a do { } while loop and the right hand side of
         * the conditional when adjusting will evaluate to false (as
         * *left is set to zero before the loop. Hence we need this
         * adjust - even if we reset it at the start of the loop.
         */
        if ( adjust )
            adjust = 0; /* Used when adjusting the 'max_batch_sz' or 'retries'. */

        nr = min(max - *done, max_batch_sz);

        sysctl.u.livepatch.u.list.nr = nr;
        /* Fix the size (may vary between hypercalls). */
        HYPERCALL_BOUNCE_SET_SIZE(info, nr * sizeof(*info));
        HYPERCALL_BOUNCE_SET_SIZE(name, name_sz);
        HYPERCALL_BOUNCE_SET_SIZE(len, nr * sizeof(*len));
        HYPERCALL_BOUNCE_SET_SIZE(metadata, metadata_sz);
        HYPERCALL_BOUNCE_SET_SIZE(metadata_len, nr * sizeof(*metadata_len));
        /* Move the pointer to proper offset into 'info'. */
        (HYPERCALL_BUFFER(info))->ubuf = info + *done;
        (HYPERCALL_BUFFER(name))->ubuf = name + name_off;
        (HYPERCALL_BUFFER(len))->ubuf = len + *done;
        (HYPERCALL_BUFFER(metadata))->ubuf = metadata + metadata_off;
        (HYPERCALL_BUFFER(metadata_len))->ubuf = metadata_len + *done;
        /* Allocate memory. */
        rc = xc_hypercall_bounce_pre(xch, info);
        if ( rc )
            break;

        rc = xc_hypercall_bounce_pre(xch, name);
        if ( rc )
            break;

        rc = xc_hypercall_bounce_pre(xch, len);
        if ( rc )
            break;

        rc = xc_hypercall_bounce_pre(xch, metadata);
        if ( rc )
            break;

        rc = xc_hypercall_bounce_pre(xch, metadata_len);
        if ( rc )
            break;

        set_xen_guest_handle(sysctl.u.livepatch.u.list.status, info);
        set_xen_guest_handle(sysctl.u.livepatch.u.list.name, name);
        set_xen_guest_handle(sysctl.u.livepatch.u.list.len, len);
        set_xen_guest_handle(sysctl.u.livepatch.u.list.metadata, metadata);
        set_xen_guest_handle(sysctl.u.livepatch.u.list.metadata_len, metadata_len);

        rc = do_sysctl(xch, &sysctl);
        /*
         * From here on we MUST call xc_hypercall_bounce. If rc < 0 we
         * end up doing it (outside the loop), so using a break is OK.
         */
        if ( rc < 0 && errno == E2BIG )
        {
            if ( max_batch_sz <= 1 )
                break;
            max_batch_sz >>= 1;
            adjust = 1; /* For the loop conditional to let us loop again. */
            /* No memory leaks! */
            xc_hypercall_bounce_post(xch, info);
            xc_hypercall_bounce_post(xch, name);
            xc_hypercall_bounce_post(xch, len);
            xc_hypercall_bounce_post(xch, metadata);
            xc_hypercall_bounce_post(xch, metadata_len);
            continue;
        }

        if ( rc < 0 ) /* For all other errors we bail out. */
            break;

        if ( !version )
            version = sysctl.u.livepatch.u.list.version;

        if ( sysctl.u.livepatch.u.list.version != version )
        {
            /* We could make this configurable as parameter? */
            if ( retries++ > 3 )
            {
                rc = -1;
                errno = EBUSY;
                break;
            }
            *done = 0; /* Retry from scratch. */
            version = sysctl.u.livepatch.u.list.version;
            adjust = 1; /* And make sure we continue in the loop. */
            /* No memory leaks. */
            xc_hypercall_bounce_post(xch, info);
            xc_hypercall_bounce_post(xch, name);
            xc_hypercall_bounce_post(xch, len);
            xc_hypercall_bounce_post(xch, metadata);
            xc_hypercall_bounce_post(xch, metadata_len);
            continue;
        }

        /* We should never hit this, but just in case. */
        if ( rc > nr )
        {
            errno = EOVERFLOW; /* Overflow! */
            rc = -1;
            break;
        }
        *left = sysctl.u.livepatch.u.list.nr; /* Total remaining count. */
        _name_sz = sysctl.u.livepatch.u.list.name_total_size; /* Total received name size. */
        _metadata_sz = sysctl.u.livepatch.u.list.metadata_total_size; /* Total received metadata size. */
        /* Copy only up 'rc' of data' - we could add 'min(rc,nr) if desired. */
        HYPERCALL_BOUNCE_SET_SIZE(info, (rc * sizeof(*info)));
        HYPERCALL_BOUNCE_SET_SIZE(name, _name_sz);
        HYPERCALL_BOUNCE_SET_SIZE(len, (rc * sizeof(*len)));
        HYPERCALL_BOUNCE_SET_SIZE(metadata, _metadata_sz);
        HYPERCALL_BOUNCE_SET_SIZE(metadata_len, (rc * sizeof(*metadata_len)));
        /* Bounce the data and free the bounce buffer. */
        xc_hypercall_bounce_post(xch, info);
        xc_hypercall_bounce_post(xch, name);
        xc_hypercall_bounce_post(xch, len);
        xc_hypercall_bounce_post(xch, metadata);
        xc_hypercall_bounce_post(xch, metadata_len);

        name_sz -= _name_sz;
        name_off += _name_sz;
        metadata_sz -= _metadata_sz;
        metadata_off += _metadata_sz;

        /* And update how many elements of info we have copied into. */
        *done += rc;
        /* Update idx. */
        sysctl.u.livepatch.u.list.idx = *done;
    } while ( adjust || (*done < max && *left != 0) );

    if ( rc < 0 )
    {
        xc_hypercall_bounce_post(xch, len);
        xc_hypercall_bounce_post(xch, name);
        xc_hypercall_bounce_post(xch, info);
        xc_hypercall_bounce_post(xch, metadata);
        xc_hypercall_bounce_post(xch, metadata_len);
    }

    return rc > 0 ? 0 : rc;
}

static int _xc_livepatch_action(xc_interface *xch,
                                char *name,
                                unsigned int action,
                                uint32_t timeout,
                                uint32_t flags)
{
    int rc;
    DECLARE_SYSCTL;
    /* The size is figured out when we strlen(name) */
    DECLARE_HYPERCALL_BOUNCE(name, 0, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    struct xen_livepatch_name def_name = { };

    def_name.size = strlen(name) + 1;

    if ( def_name.size > XEN_LIVEPATCH_NAME_SIZE )
    {
        errno = EINVAL;
        return -1;
    }

    HYPERCALL_BOUNCE_SET_SIZE(name, def_name.size);

    if ( xc_hypercall_bounce_pre(xch, name) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_livepatch_op;
    sysctl.u.livepatch.cmd = XEN_SYSCTL_LIVEPATCH_ACTION;
    sysctl.u.livepatch.pad = 0;
    sysctl.u.livepatch.u.action.cmd = action;
    sysctl.u.livepatch.u.action.timeout = timeout;
    sysctl.u.livepatch.u.action.flags = flags;
    sysctl.u.livepatch.u.action.pad = 0;

    sysctl.u.livepatch.u.action.name = def_name;
    set_xen_guest_handle(sysctl.u.livepatch.u.action.name.name, name);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, name);

    return rc;
}

int xc_livepatch_apply(xc_interface *xch, char *name, uint32_t timeout, uint32_t flags)
{
    return _xc_livepatch_action(xch, name, LIVEPATCH_ACTION_APPLY, timeout, flags);
}

int xc_livepatch_revert(xc_interface *xch, char *name, uint32_t timeout, uint32_t flags)
{
    return _xc_livepatch_action(xch, name, LIVEPATCH_ACTION_REVERT, timeout, flags);
}

int xc_livepatch_unload(xc_interface *xch, char *name, uint32_t timeout, uint32_t flags)
{
    return _xc_livepatch_action(xch, name, LIVEPATCH_ACTION_UNLOAD, timeout, flags);
}

int xc_livepatch_replace(xc_interface *xch, char *name, uint32_t timeout, uint32_t flags)
{
    return _xc_livepatch_action(xch, name, LIVEPATCH_ACTION_REPLACE, timeout, flags);
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
