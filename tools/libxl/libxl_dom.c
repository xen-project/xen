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

#include "libxl_osdeps.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h> /* for struct timeval */
#include <unistd.h> /* for sleep(2) */

#include <xenctrl.h>
#include <xc_dom.h>
#include <xenguest.h>

#include "libxl.h"
#include "libxl_internal.h"

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
    if (info->timer_mode != -1)
        xc_set_hvm_param(ctx->xch, domid, HVM_PARAM_TIMER_MODE,
                (unsigned long) info->timer_mode);
    if (info->hpet != -1)
        xc_set_hvm_param(ctx->xch, domid, HVM_PARAM_HPET_ENABLED, (unsigned long) info->hpet);
    if (info->vpt_align != -1)
        xc_set_hvm_param(ctx->xch, domid, HVM_PARAM_VPT_ALIGN, (unsigned long) info->vpt_align);
    xc_domain_max_vcpus(ctx->xch, domid, info->max_vcpus);
    xc_domain_setmaxmem(ctx->xch, domid, info->target_memkb + LIBXL_MAXMEM_CONSTANT);
    xc_domain_set_memmap_limit(ctx->xch, domid, 
            (info->hvm) ? info->max_memkb : 
            (info->max_memkb + info->u.pv.slack_memkb));

    if (info->hvm) {
        unsigned long shadow;
        shadow = (info->shadow_memkb + 1023) / 1024;
        xc_shadow_control(ctx->xch, domid, XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION, NULL, 0, &shadow, 0, NULL);
    }

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
    int i;

    ents = libxl_calloc(ctx, (10 + info->max_vcpus) * 2, sizeof(char *));
    ents[0] = "memory/static-max";
    ents[1] = libxl_sprintf(ctx, "%d", info->max_memkb);
    ents[2] = "memory/target";
    ents[3] = libxl_sprintf(ctx, "%d", info->target_memkb);
    ents[2] = "memory/videoram";
    ents[3] = libxl_sprintf(ctx, "%d", info->video_memkb);
    ents[4] = "domid";
    ents[5] = libxl_sprintf(ctx, "%d", domid);
    ents[6] = "store/port";
    ents[7] = libxl_sprintf(ctx, "%"PRIu32, state->store_port);
    ents[8] = "store/ring-ref";
    ents[9] = libxl_sprintf(ctx, "%lu", state->store_mfn);
    for (i = 0; i < info->max_vcpus; i++) {
        ents[10+(i*2)]   = libxl_sprintf(ctx, "cpu/%d/availability", i);
        ents[10+(i*2)+1] = (i && info->cur_vcpus && (i >= info->cur_vcpus))
                            ? "offline" : "online";
    }

    dom_path = libxl_xs_get_dompath(ctx, domid);
    if (!dom_path)
        return ERROR_FAIL;

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
    free(vm_path);
    libxl_free(ctx, ents);
    libxl_free(ctx, dom_path);
    return 0;
}

int build_pv(struct libxl_ctx *ctx, uint32_t domid,
             libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    struct xc_dom_image *dom;
    int ret;
    int flags = 0;

    dom = xc_dom_allocate(info->u.pv.cmdline, info->u.pv.features);
    if (!dom) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xc_dom_allocate failed");
        return -1;
    }
    if ((ret = xc_dom_linux_build(ctx->xch, dom, domid, info->target_memkb / 1024,
                                  info->kernel, info->u.pv.ramdisk, flags,
                                  state->store_port, &state->store_mfn,
                                  state->console_port, &state->console_mfn)) != 0) {
        xc_dom_release(dom);
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "xc_dom_linux_build failed");
        return -2;
    }
    xc_dom_release(dom);
    return 0;
}

int build_hvm(struct libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    int ret;

    ret = xc_hvm_build_target_mem(ctx->xch, domid, (info->max_memkb - info->video_memkb) / 1024, (info->target_memkb - info->video_memkb) / 1024, info->kernel);
    if (ret) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "hvm building failed");
        return ERROR_FAIL;
    }
    ret = hvm_build_set_params(ctx->xch, domid, info->u.hvm.apic, info->u.hvm.acpi,
                               info->u.hvm.pae, info->u.hvm.nx, info->u.hvm.viridian,
                               info->max_vcpus,
                               state->store_port, &state->store_mfn);
    if (ret) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "hvm build set params failed");
        return ERROR_FAIL;
    }
#if defined(__i386__) || defined(__x86_64__)
    xc_cpuid_apply_policy(ctx->xch, domid);
#endif
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
#if defined(__i386__) || defined(__x86_64__)
    xc_cpuid_apply_policy(ctx->xch, domid);
#endif
    return 0;
}

struct suspendinfo {
    struct libxl_ctx *ctx;
    int xce; /* event channel handle */
    int suspend_eventchn;
    int domid;
    int hvm;
    unsigned int flags;
};

static void core_suspend_switch_qemu_logdirty(int domid, unsigned int enable)
{
    struct xs_handle *xsh;
    char path[64];

    snprintf(path, sizeof(path), "/local/domain/0/device-model/%u/logdirty/cmd", domid);

    xsh = xs_daemon_open();

    if (enable)
        xs_write(xsh, XBT_NULL, path, "enable", strlen("enable"));
    else
        xs_write(xsh, XBT_NULL, path, "disable", strlen("disable"));

    xs_daemon_close(xsh);
}

static int core_suspend_callback(void *data)
{
    struct suspendinfo *si = data;
    unsigned long s_state = 0;
    int ret;
    char *path, *state = "suspend";
    int watchdog = 60;

    if (si->hvm)
        xc_get_hvm_param(si->ctx->xch, si->domid, HVM_PARAM_ACPI_S_STATE, &s_state);
    if ((s_state == 0) && (si->suspend_eventchn >= 0)) {
        ret = xc_evtchn_notify(si->xce, si->suspend_eventchn);
        if (ret < 0) {
            XL_LOG(si->ctx, XL_LOG_ERROR, "xc_evtchn_notify failed ret=%d", ret);
            return 0;
        }
        ret = xc_await_suspend(si->xce, si->suspend_eventchn);
        if (ret < 0) {
            XL_LOG(si->ctx, XL_LOG_ERROR, "xc_await_suspend failed ret=%d", ret);
            return 0;
        }
        return 1;
    }
    path = libxl_sprintf(si->ctx, "%s/control/shutdown", libxl_xs_get_dompath(si->ctx, si->domid));
    libxl_xs_write(si->ctx, XBT_NULL, path, "suspend", strlen("suspend"));
    if (si->hvm) {
        unsigned long hvm_pvdrv, hvm_s_state;
        xc_get_hvm_param(si->ctx->xch, si->domid, HVM_PARAM_CALLBACK_IRQ, &hvm_pvdrv);
        xc_get_hvm_param(si->ctx->xch, si->domid, HVM_PARAM_ACPI_S_STATE, &hvm_s_state);
        if (!hvm_pvdrv || hvm_s_state) {
            XL_LOG(si->ctx, XL_LOG_DEBUG, "Calling xc_domain_shutdown on the domain");
            xc_domain_shutdown(si->ctx->xch, si->domid, SHUTDOWN_suspend);
        }
    }
    XL_LOG(si->ctx, XL_LOG_DEBUG, "wait for the guest to suspend");
    while (!strcmp(state, "suspend") && watchdog > 0) {
        int nb_domain, i;
        xc_dominfo_t *list = NULL;
        usleep(100000);
        list = libxl_domain_infolist(si->ctx, &nb_domain);
        for (i = 0; i < nb_domain; i++) {
            if (si->domid == list[i].domid) {
                if (list[i].shutdown != 0 && list[i].shutdown_reason == SHUTDOWN_suspend) {
                    free(list);
                    return 1;
                }
            }
        }
        free(list);
        state = libxl_xs_read(si->ctx, XBT_NULL, path);
        watchdog--;
    }
    if (!strcmp(state, "suspend")) {
        XL_LOG(si->ctx, XL_LOG_ERROR, "guest didn't suspend in time");
        libxl_xs_write(si->ctx, XBT_NULL, path, "", 1);
    }
    return 1;
}

int core_suspend(struct libxl_ctx *ctx, uint32_t domid, int fd,
		int hvm, int live, int debug)
{
    int flags;
    int port;
    struct save_callbacks callbacks;
    struct suspendinfo si;

    flags = (live) ? XCFLAGS_LIVE : 0
          | (debug) ? XCFLAGS_DEBUG : 0
          | (hvm) ? XCFLAGS_HVM : 0;

    si.domid = domid;
    si.flags = flags;
    si.hvm = hvm;
    si.ctx = ctx;
    si.suspend_eventchn = -1;

    si.xce = xc_evtchn_open();
    if (si.xce < 0)
        return -1;

    if (si.xce > 0) {
        port = xs_suspend_evtchn_port(si.domid);

        if (port < 0) {
            XL_LOG(ctx, XL_LOG_WARNING, "Failed to get the suspend evtchn port");
        } else {
            si.suspend_eventchn = xc_suspend_evtchn_init(si.ctx->xch, si.xce, si.domid, port);

            if (si.suspend_eventchn < 0)
                XL_LOG(ctx, XL_LOG_WARNING, "Suspend event channel initialization failed");
        }
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.suspend = core_suspend_callback;
    callbacks.data = &si;

    xc_domain_save(ctx->xch, fd, domid, 0, 0, flags,
                   &callbacks, hvm,
                   &core_suspend_switch_qemu_logdirty);

    if (si.suspend_eventchn > 0)
        xc_suspend_evtchn_release(si.xce, si.suspend_eventchn);
    if (si.xce > 0)
        xc_evtchn_close(si.xce);

    return 0;
}

