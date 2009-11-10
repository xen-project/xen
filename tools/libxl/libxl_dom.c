/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl.h"
#include "libxl_internal.h"
#include <inttypes.h>
#include <xenguest.h>
#include <string.h>
#include <sys/time.h> /* for struct timeval */
#include <unistd.h> /* for sleep(2) */

int is_hvm(struct libxl_ctx *ctx, uint32_t domid)
{
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (ret != 1)
        return -1;
    if (info.domain != domid)
        return -1;
    return !!(info.flags & XEN_DOMINF_hvm_guest);
}

int build_pre(struct libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    unsigned long shadow;
    if (info->timer_mode != -1)
        xc_set_hvm_param(ctx->xch, domid, HVM_PARAM_TIMER_MODE,
                (unsigned long) info->timer_mode);
    if (info->hpet != -1)
        xc_set_hvm_param(ctx->xch, domid, HVM_PARAM_HPET_ENABLED, (unsigned long) info->hpet);
    if (info->vpt_align != -1)
        xc_set_hvm_param(ctx->xch, domid, HVM_PARAM_VPT_ALIGN, (unsigned long) info->vpt_align);
    xc_domain_max_vcpus(ctx->xch, domid, info->max_vcpus);
    xc_domain_setmaxmem(ctx->xch, domid, info->max_memkb + info->video_memkb);
    xc_domain_set_memmap_limit(ctx->xch, domid, info->max_memkb);
    shadow = (info->shadow_memkb + 1023) / 1024;
    xc_shadow_control(ctx->xch, domid, XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION, NULL, 0, &shadow, 0, NULL);

    state->store_port = xc_evtchn_alloc_unbound(ctx->xch, domid, 0);
    state->console_port = xc_evtchn_alloc_unbound(ctx->xch, domid, 0);
    return 0;
}

int build_post(struct libxl_ctx *ctx, uint32_t domid,
               libxl_domain_build_info *info, libxl_domain_build_state *state,
               char **vms_ents, char **local_ents)
{
    char *dom_path, *vm_path;
    xs_transaction_t t;
    char **ents;

    ents = libxl_calloc(ctx, 6 * 2, sizeof(char *));
    ents[0] = libxl_sprintf(ctx, "memory/static-max");
    ents[1] = libxl_sprintf(ctx, "%d", info->max_memkb);
    ents[2] = libxl_sprintf(ctx, "memory/target");
    ents[3] = libxl_sprintf(ctx, "%d", info->max_memkb); /* PROBABLY WRONG */
    ents[4] = libxl_sprintf(ctx, "domid");
    ents[5] = libxl_sprintf(ctx, "%d", domid);
    ents[6] = libxl_sprintf(ctx, "store/port");
    ents[7] = libxl_sprintf(ctx, "%"PRIu32, state->store_port);
    ents[8] = libxl_sprintf(ctx, "store/ring-ref");
    ents[9] = libxl_sprintf(ctx, "%lu", state->store_mfn);

    dom_path = libxl_xs_get_dompath(ctx, domid);
    vm_path = xs_read(ctx->xsh, XBT_NULL, libxl_sprintf(ctx, "%s/vm", dom_path), NULL);
retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    libxl_xs_writev(ctx, t, dom_path, ents);
    libxl_xs_writev(ctx, t, dom_path, local_ents);
    libxl_xs_writev(ctx, t, vm_path, vms_ents);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    xs_introduce_domain(ctx->xsh, domid, state->store_mfn, state->store_port);
    return 0;
}

int build_pv(struct libxl_ctx *ctx, uint32_t domid,
             libxl_domain_build_info *info, libxl_domain_build_state *state)
{
#if 0 /* unused variables */
    int mem_target_kib = info->max_memkb;
    char *domid_str = libxl_sprintf(ctx, "%d", domid);
    char *memsize_str = libxl_sprintf(ctx, "%d", mem_target_kib / 1024);
    char *store_port_str = libxl_sprintf(ctx, "%d", state->store_port);
    char *console_port_str = libxl_sprintf(ctx, "%d", state->console_port);
#endif
    return ERROR_NI;
}

int build_hvm(struct libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    int ret;

    ret = xc_hvm_build(ctx->xch, domid, info->max_memkb / 1024, info->kernel);
    if (ret) {
        XL_LOG(ctx, XL_LOG_ERROR, "hvm building failed: %d", ret);
        return ERROR_FAIL;
    }
    ret = hvm_build_set_params(ctx->xch, domid, info->u.hvm.apic, info->u.hvm.acpi,
                               info->u.hvm.pae, info->u.hvm.nx, info->u.hvm.viridian,
                               info->max_vcpus,
                               state->store_port, &state->store_mfn);
    if (ret) {
        XL_LOG(ctx, XL_LOG_ERROR, "hvm build set params failed: %d", ret);
        return ERROR_FAIL;
    }
    xc_cpuid_apply_policy(ctx->xch, domid);
    return 0;
}

int restore_common(struct libxl_ctx *ctx, uint32_t domid,
                   libxl_domain_build_info *info, libxl_domain_build_state *state,
                   int fd)
{
    /* read signature */
    xc_domain_restore(ctx->xch, fd, domid,
                      state->store_port, &state->store_mfn,
                      state->console_port, &state->console_mfn,
                      info->hvm, info->u.hvm.pae, 0);
    return 0;
}

/* the following code is extremely ugly and racy without forking.
   we intend to fix the re-entrancy of the underlying code instead of forking */
static struct libxl_ctx *global_suspend_ctx = NULL;
static struct suspendinfo {
    int xch;
    int xce; /* event channel handle */
    int suspend_eventchn;
    int domid;
    int hvm;
    unsigned int flags;
} si;

void core_suspend_switch_qemu_logdirty(int domid, unsigned int enable)
{
    struct xs_handle *xs;
    char *path, *ret_path, *cmd_path, *ret_str, *cmd_str, **watch;
    unsigned int len;
    struct timeval tv;
    fd_set fdset;
    struct libxl_ctx *ctx = global_suspend_ctx;

    xs = xs_daemon_open();
    if (!xs)
        return;
    path = libxl_sprintf(ctx, "/local/domain/0/device-model/%i/logdirty", domid);
    if (!path)
        return;
    ret_path = libxl_sprintf(ctx, "%s/ret", path);
    if (!ret_path)
        return;
    cmd_path = libxl_sprintf(ctx, "%s/cmd", path);
    if (!ret_path)
        return;

    /* Watch for qemu's return value */
    if (!xs_watch(xs, ret_path, "qemu-logdirty-ret"))
        return;

    cmd_str = (enable == 0) ? "disable" : "enable";

    /* Tell qemu that we want it to start logging dirty page to Xen */
    if (!xs_write(xs, XBT_NULL, cmd_path, cmd_str, strlen(cmd_str)))
        return;

    /* Wait a while for qemu to signal that it has service logdirty command */
read_again:
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_ZERO(&fdset);
    FD_SET(xs_fileno(xs), &fdset);

    if ((select(xs_fileno(xs) + 1, &fdset, NULL, NULL, &tv)) != 1)
        return;

    watch = xs_read_watch(xs, &len);
    free(watch);

    ret_str = xs_read(xs, XBT_NULL, ret_path, &len);
    if (ret_str == NULL || strcmp(ret_str, cmd_str))
        /* Watch fired but value is not yet right */
        goto read_again;
    free(ret_str);
}

static int core_suspend_callback(void *data)
{
    struct suspendinfo *si = data;
    unsigned long s_state = 0;
    int ret;

    if (si->hvm)
        xc_get_hvm_param(si->xch, si->domid, HVM_PARAM_ACPI_S_STATE, &s_state);
    if ((s_state == 0) && (si->suspend_eventchn >= 0)) {
        ret = xc_evtchn_notify(si->xch, si->suspend_eventchn);
        if (ret < 0) {
            return 0;
        }
        ret = xc_await_suspend(si->xch, si->suspend_eventchn);
        if (ret < 0) {
            return 0;
        }
        return 1;
    }
    /* need to shutdown (to suspend) the domain here */
    return 0;
}

static struct save_callbacks callbacks;

int core_suspend(struct libxl_ctx *ctx, uint32_t domid, int fd,
		int hvm, int live, int debug)
{
    int flags;
    int port;

    flags = (live) ? XCFLAGS_LIVE : 0
          | (debug) ? XCFLAGS_DEBUG : 0;

    /* crappy global lock until we make everything clean */
    while (global_suspend_ctx) {
        sleep(1);
    }
    global_suspend_ctx = ctx;

    si.domid = domid;
    si.flags = flags;
    si.hvm = hvm;
    si.suspend_eventchn = si.xce = -1;
    si.xch = ctx->xch;

    si.xce = xc_evtchn_open();
    if (si.xce < 0)
        return -1;

    if (si.xce > 0) {
        port = xs_suspend_evtchn_port(si.domid);

        if (port < 0) {
        } else {
            si.suspend_eventchn = xc_suspend_evtchn_init(si.xch, si.xce, si.domid, port);

            if (si.suspend_eventchn < 0) {
            }
        }
    }

    callbacks.suspend = core_suspend_callback;
    callbacks.postcopy = NULL;
    callbacks.checkpoint = NULL;
    callbacks.data = &si;

    xc_domain_save(ctx->xch, fd, domid, 0, 0, flags,
                   &callbacks, hvm,
                   core_suspend_switch_qemu_logdirty);

    if (si.suspend_eventchn > 0)
        xc_suspend_evtchn_release(si.xce, si.suspend_eventchn);
    if (si.xce > 0)
        xc_evtchn_close(si.xce);

    global_suspend_ctx = NULL;
    return 0;
}
