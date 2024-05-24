#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <inttypes.h>
#include <xenstore.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <libxl.h>
#include <xenevtchn.h>
#include <xenforeignmemory.h>
#include <xen/io/xs_wire.h>

#include "init-dom-json.h"

#define STR_MAX_LENGTH 128

static int get_xs_page(struct xc_interface_core *xch, libxl_dominfo *info,
                       uint64_t *xenstore_pfn)
{
    int rc;

    rc = xc_hvm_param_get(xch, info->domid, HVM_PARAM_STORE_PFN, xenstore_pfn);
    if (rc < 0) {
        fprintf(stderr,"Failed to get HVM_PARAM_STORE_PFN\n");
        return 1;
    }

    return 0;
}

static bool do_xs_write_dom(struct xs_handle *xsh, xs_transaction_t t,
                            domid_t domid, char *path, char *val)
{
    char full_path[STR_MAX_LENGTH];
    struct xs_permissions perms[2];
    int rc;

    perms[0].id = domid;
    perms[0].perms = XS_PERM_NONE;
    perms[1].id = 0;
    perms[1].perms = XS_PERM_READ;

    rc = snprintf(full_path, STR_MAX_LENGTH,
                  "/local/domain/%u/%s", domid, path);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return false;
    if (!xs_write(xsh, t, full_path, val, strlen(val)))
        return false;
    return xs_set_permissions(xsh, t, full_path, perms, 2);
}

static bool do_xs_write_libxl(struct xs_handle *xsh, xs_transaction_t t,
                              domid_t domid, char *path, char *val)
{
    char full_path[STR_MAX_LENGTH];
    int rc;

    rc = snprintf(full_path, STR_MAX_LENGTH,
                  "/libxl/%u/%s", domid, path);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return false;
    return xs_write(xsh, t, full_path, val, strlen(val));
}

static bool do_xs_write_vm(struct xs_handle *xsh, xs_transaction_t t,
                           libxl_uuid uuid, char *path, char *val)
{
    char full_path[STR_MAX_LENGTH];
    int rc;

    rc = snprintf(full_path, STR_MAX_LENGTH,
                  "/vm/" LIBXL_UUID_FMT "/%s", LIBXL_UUID_BYTES(uuid), path);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return false;
    return xs_write(xsh, t, full_path, val, strlen(val));
}

/*
 * The xenstore nodes are the xenstore nodes libxl writes at domain
 * creation.
 *
 * The list was retrieved by running xenstore-ls on a corresponding
 * domain started by xl/libxl.
 */
static int create_xenstore(struct xs_handle *xsh,
                           libxl_dominfo *info, libxl_uuid uuid,
                           uint64_t xenstore_pfn,
                           evtchn_port_t xenstore_port)
{
    domid_t domid;
    unsigned int i;
    char uuid_str[STR_MAX_LENGTH];
    char dom_name_str[STR_MAX_LENGTH];
    char vm_val_str[STR_MAX_LENGTH];
    char id_str[STR_MAX_LENGTH];
    char max_memkb_str[STR_MAX_LENGTH];
    char target_memkb_str[STR_MAX_LENGTH];
    char cpu_str[STR_MAX_LENGTH];
    char xenstore_port_str[STR_MAX_LENGTH];
    char ring_ref_str[STR_MAX_LENGTH];
    xs_transaction_t t;
    struct timeval start_time;
    char start_time_str[STR_MAX_LENGTH];
    int rc;

    if (gettimeofday(&start_time, NULL) < 0)
        return -errno;
    rc = snprintf(start_time_str, STR_MAX_LENGTH, "%jd.%02d",
            (intmax_t)start_time.tv_sec, (int)start_time.tv_usec / 10000);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;

    domid = info->domid;
    rc = snprintf(id_str, STR_MAX_LENGTH, "%u", domid);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(dom_name_str, STR_MAX_LENGTH, "dom0less-%u", domid);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(uuid_str, STR_MAX_LENGTH, LIBXL_UUID_FMT, LIBXL_UUID_BYTES(uuid));
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(vm_val_str, STR_MAX_LENGTH,
                  "vm/" LIBXL_UUID_FMT, LIBXL_UUID_BYTES(uuid));
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(max_memkb_str, STR_MAX_LENGTH, "%"PRIu64, info->max_memkb);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(target_memkb_str, STR_MAX_LENGTH, "%"PRIu64, info->current_memkb);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(ring_ref_str, STR_MAX_LENGTH, "%"PRIu64, xenstore_pfn);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;
    rc = snprintf(xenstore_port_str, STR_MAX_LENGTH, "%u", xenstore_port);
    if (rc < 0 || rc >= STR_MAX_LENGTH)
        return rc;

retry_transaction:
    t = xs_transaction_start(xsh);
    if (t == XBT_NULL)
        return -errno;

    rc = -EIO;
    /* /vm */
    if (!do_xs_write_vm(xsh, t, uuid, "name", dom_name_str)) goto err;
    if (!do_xs_write_vm(xsh, t, uuid, "uuid", uuid_str)) goto err;
    if (!do_xs_write_vm(xsh, t, uuid, "start_time", start_time_str)) goto err;

    /* /domain */
    if (!do_xs_write_dom(xsh, t, domid, "vm", vm_val_str)) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "name", dom_name_str)) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "cpu", "")) goto err;
    for (i = 0; i < info->vcpu_max_id; i++) {
        rc = snprintf(cpu_str, STR_MAX_LENGTH, "cpu/%u/availability/", i);
        if (rc < 0 || rc >= STR_MAX_LENGTH)
            goto err;
        rc = -EIO;
        if (!do_xs_write_dom(xsh, t, domid, cpu_str,
                             (info->cpupool & (1 << i)) ? "online" : "offline"))
            goto err;
    }

    if (!do_xs_write_dom(xsh, t, domid, "memory", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "memory/static-max", max_memkb_str)) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "memory/target", target_memkb_str)) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "memory/videoram", "-1")) goto err;

    if (!do_xs_write_dom(xsh, t, domid, "device", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "device/suspend", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "device/suspend/event-channel", "")) goto err;

    if (!do_xs_write_dom(xsh, t, domid, "control", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/shutdown", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/feature-poweroff", "1")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/feature-reboot", "1")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/feature-suspend", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/sysrq", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/platform-feature-multiprocessor-suspend", "1")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "control/platform-feature-xs_reset_watches", "1")) goto err;

    if (!do_xs_write_dom(xsh, t, domid, "domid", id_str)) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "data", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "drivers", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "feature", "")) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "attr", "")) goto err;

    if (!do_xs_write_dom(xsh, t, domid, "store/port", xenstore_port_str)) goto err;
    if (!do_xs_write_dom(xsh, t, domid, "store/ring-ref", ring_ref_str)) goto err;

    if (!do_xs_write_libxl(xsh, t, domid, "type", "pvh")) goto err;
    if (!do_xs_write_libxl(xsh, t, domid, "dm-version", "qemu_xen")) goto err;

    if (!xs_transaction_end(xsh, t, false)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else
            return -errno;
    }

    return 0;

err:
    xs_transaction_end(xsh, t, true);
    return rc;
}

static int init_domain(struct xs_handle *xsh,
                       struct xc_interface_core *xch,
                       xenforeignmemory_handle *xfh,
                       libxl_dominfo *info)
{
    libxl_uuid uuid;
    uint64_t xenstore_evtchn, xenstore_pfn;
    int rc;

    printf("Init dom0less domain: %u\n", info->domid);

    rc = xc_hvm_param_get(xch, info->domid, HVM_PARAM_STORE_EVTCHN,
                          &xenstore_evtchn);
    if (rc != 0) {
        printf("Failed to get HVM_PARAM_STORE_EVTCHN\n");
        return 1;
    }

    /* no xen,enhanced; nothing to do */
    if (!xenstore_evtchn)
        return 0;

    /* Get xenstore page */
    if (get_xs_page(xch, info, &xenstore_pfn) != 0) {
        fprintf(stderr,"Error on getting xenstore page\n");
        return 1;
    }

    rc = xc_dom_gnttab_seed(xch, info->domid, true,
                            (xen_pfn_t)-1, xenstore_pfn, 0, 0);
    if (rc)
        err(1, "xc_dom_gnttab_seed");

    libxl_uuid_generate(&uuid);
    xc_domain_sethandle(xch, info->domid, libxl_uuid_bytearray(&uuid));

    rc = gen_stub_json_config(info->domid, &uuid);
    if (rc)
        err(1, "gen_stub_json_config");

    rc = create_xenstore(xsh, info, uuid, xenstore_pfn, xenstore_evtchn);
    if (rc)
        err(1, "writing to xenstore");

    rc = xs_introduce_domain(xsh, info->domid, xenstore_pfn, xenstore_evtchn);
    if (!rc)
        err(1, "xs_introduce_domain");
    return 0;
}

/* Check if domain has been configured in XS */
static bool domain_exists(struct xs_handle *xsh, int domid)
{
    return xs_is_domain_introduced(xsh, domid);
}

int main(int argc, char **argv)
{
    libxl_dominfo *info = NULL;
    libxl_ctx *ctx;
    int nb_vm = 0, rc = 0, i;
    struct xs_handle *xsh = NULL;
    struct xc_interface_core *xch = NULL;
    xenforeignmemory_handle *xfh = NULL;

    /* TODO reuse libxl xsh connection */
    xsh = xs_open(0);
    xch = xc_interface_open(0, 0, 0);
    xfh = xenforeignmemory_open(0, 0);
    if (xsh == NULL || xch == NULL || xfh == NULL) {
        fprintf(stderr, "Cannot open xc/xs/xenforeignmemory interfaces");
        rc = -errno;
        goto out;
    }

    rc = libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, NULL);
    if (rc) {
        fprintf(stderr, "cannot init xl context\n");
        goto out;
    }

    info = libxl_list_domain(ctx, &nb_vm);
    if (!info) {
        fprintf(stderr, "libxl_list_vm failed.\n");
        rc = -1;
        goto out;
    }

    for (i = 0; i < nb_vm; i++) {
        domid_t domid = info[i].domid;

        /* Don't need to check for Dom0 */
        if (!domid)
            continue;

        printf("Checking domid: %u\n", domid);
        if (!domain_exists(xsh, domid)) {
            rc = init_domain(xsh, xch, xfh, &info[i]);
            if (rc < 0) {
                fprintf(stderr, "init_domain failed.\n");
                goto out;
            }
        } else {
            printf("Domain %u has already been initialized\n", domid);
        }
    }
out:
    libxl_dominfo_list_free(info, nb_vm);
    return rc;
}
