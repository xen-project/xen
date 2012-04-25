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

#include "libxl_osdeps.h" /* must come before any other headers */

#include <glob.h>

#include <xenctrl.h>
#include <xc_dom.h>
#include <xenguest.h>

#include <xen/hvm/hvm_info_table.h>

#include "libxl_internal.h"

libxl_domain_type libxl__domain_type(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (ret != 1)
        return -1;
    if (info.domain != domid)
        return -1;
    if (info.flags & XEN_DOMINF_hvm_guest)
        return LIBXL_DOMAIN_TYPE_HVM;
    else
        return LIBXL_DOMAIN_TYPE_PV;
}

int libxl__sched_set_params(libxl__gc *gc, uint32_t domid, libxl_sched_params *scparams)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_scheduler sched;
    libxl_sched_sedf_domain sedf_info;
    libxl_sched_credit_domain credit_info;
    libxl_sched_credit2_domain credit2_info;
    int ret;

    sched = libxl_get_scheduler (ctx);
    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
      sedf_info.period = scparams->period;
      sedf_info.slice = scparams->slice;
      sedf_info.latency = scparams->latency;
      sedf_info.extratime = scparams->extratime;
      sedf_info.weight = scparams->weight;
      ret=libxl_sched_sedf_domain_set(ctx, domid, &sedf_info);
      break;
    case LIBXL_SCHEDULER_CREDIT:
      credit_info.weight = scparams->weight;
      credit_info.cap = scparams->cap;
      ret=libxl_sched_credit_domain_set(ctx, domid, &credit_info);
      break;
    case LIBXL_SCHEDULER_CREDIT2:
      credit2_info.weight = scparams->weight;
      ret=libxl_sched_credit2_domain_set(ctx, domid, &credit2_info);
      break;
    default:
      ret=-1;
    }
    return ret;
}

int libxl__domain_shutdown_reason(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (ret != 1)
        return -1;
    if (info.domain != domid)
        return -1;
    if (!(info.flags & XEN_DOMINF_shutdown))
        return -1;

    return (info.flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask;
}

int libxl__build_pre(libxl__gc *gc, uint32_t domid,
              libxl_domain_build_info *info, libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int tsc_mode;
    char *xs_domid, *con_domid;
    uint32_t rtc_timeoffset;

    xc_domain_max_vcpus(ctx->xch, domid, info->max_vcpus);
    libxl_set_vcpuaffinity_all(ctx, domid, info->max_vcpus, &info->cpumap);
    xc_domain_setmaxmem(ctx->xch, domid, info->target_memkb + LIBXL_MAXMEM_CONSTANT);
    if (info->type == LIBXL_DOMAIN_TYPE_PV)
        xc_domain_set_memmap_limit(ctx->xch, domid,
                (info->max_memkb + info->u.pv.slack_memkb));
    switch (info->tsc_mode) {
    case LIBXL_TSC_MODE_DEFAULT:
        tsc_mode = 0;
        break;
    case LIBXL_TSC_MODE_ALWAYS_EMULATE:
        tsc_mode = 1;
        break;
    case LIBXL_TSC_MODE_NATIVE:
        tsc_mode = 2;
        break;
    case LIBXL_TSC_MODE_NATIVE_PARAVIRT:
        tsc_mode = 3;
        break;
    default:
        abort();
    }
    xc_domain_set_tsc_info(ctx->xch, domid, tsc_mode, 0, 0, 0);
    if (libxl_defbool_val(info->disable_migrate))
        xc_domain_disable_migrate(ctx->xch, domid);

    rtc_timeoffset = info->rtc_timeoffset;
    if (libxl_defbool_val(info->localtime)) {
        time_t t;
        struct tm *tm;

        t = time(NULL);
        tm = localtime(&t);

        rtc_timeoffset += tm->tm_gmtoff;
    }

    if (rtc_timeoffset)
        xc_domain_set_time_offset(ctx->xch, domid, rtc_timeoffset);

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        unsigned long shadow;
        shadow = (info->shadow_memkb + 1023) / 1024;
        xc_shadow_control(ctx->xch, domid, XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION, NULL, 0, &shadow, 0, NULL);
    }

    xs_domid = xs_read(ctx->xsh, XBT_NULL, "/tool/xenstored/domid", NULL);
    state->store_domid = xs_domid ? atoi(xs_domid) : 0;
    free(xs_domid);

    con_domid = xs_read(ctx->xsh, XBT_NULL, "/tool/xenconsoled/domid", NULL);
    state->console_domid = con_domid ? atoi(con_domid) : 0;
    free(con_domid);

    state->store_port = xc_evtchn_alloc_unbound(ctx->xch, domid, state->store_domid);
    state->console_port = xc_evtchn_alloc_unbound(ctx->xch, domid, state->console_domid);
    state->vm_generationid_addr = 0;

    return 0;
}

int libxl__build_post(libxl__gc *gc, uint32_t domid,
                      libxl_domain_build_info *info,
                      libxl__domain_build_state *state,
                      char **vms_ents, char **local_ents)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *dom_path, *vm_path;
    xs_transaction_t t;
    char **ents, **hvm_ents;
    int i;

    libxl__sched_set_params (gc, domid, &(info->sched_params));

    libxl_cpuid_apply_policy(ctx, domid);
    if (info->cpuid != NULL)
        libxl_cpuid_set(ctx, domid, info->cpuid);

    ents = libxl__calloc(gc, 12 + (info->max_vcpus * 2) + 2, sizeof(char *));
    ents[0] = "memory/static-max";
    ents[1] = libxl__sprintf(gc, "%"PRId64, info->max_memkb);
    ents[2] = "memory/target";
    ents[3] = libxl__sprintf(gc, "%"PRId64,
                             info->target_memkb - info->video_memkb);
    ents[4] = "memory/videoram";
    ents[5] = libxl__sprintf(gc, "%"PRId64, info->video_memkb);
    ents[6] = "domid";
    ents[7] = libxl__sprintf(gc, "%d", domid);
    ents[8] = "store/port";
    ents[9] = libxl__sprintf(gc, "%"PRIu32, state->store_port);
    ents[10] = "store/ring-ref";
    ents[11] = libxl__sprintf(gc, "%lu", state->store_mfn);
    for (i = 0; i < info->max_vcpus; i++) {
        ents[12+(i*2)]   = libxl__sprintf(gc, "cpu/%d/availability", i);
        ents[12+(i*2)+1] = (i && info->cur_vcpus && !(info->cur_vcpus & (1 << i)))
                            ? "offline" : "online";
    }

    hvm_ents = NULL;
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        hvm_ents = libxl__calloc(gc, 3, sizeof(char *));
        hvm_ents[0] = "hvmloader/generation-id-address";
        hvm_ents[1] = libxl__sprintf(gc, "0x%lx", state->vm_generationid_addr);
    }

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        return ERROR_FAIL;
    }

    vm_path = xs_read(ctx->xsh, XBT_NULL, libxl__sprintf(gc, "%s/vm", dom_path), NULL);
retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    libxl__xs_writev(gc, t, dom_path, ents);
    if (info->type == LIBXL_DOMAIN_TYPE_HVM)
        libxl__xs_writev(gc, t, dom_path, hvm_ents);

    libxl__xs_writev(gc, t, dom_path, local_ents);
    libxl__xs_writev(gc, t, vm_path, vms_ents);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    xs_introduce_domain(ctx->xsh, domid, state->store_mfn, state->store_port);
    free(vm_path);
    return 0;
}

int libxl__build_pv(libxl__gc *gc, uint32_t domid,
             libxl_domain_build_info *info, libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    struct xc_dom_image *dom;
    int ret;
    int flags = 0;

    xc_dom_loginit(ctx->xch);

    dom = xc_dom_allocate(ctx->xch, info->u.pv.cmdline, info->u.pv.features);
    if (!dom) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_allocate failed");
        return ERROR_FAIL;
    }

    if (info->u.pv.kernel.mapped) {
        ret = xc_dom_kernel_mem(dom,
                                info->u.pv.kernel.data,
                                info->u.pv.kernel.size);
        if ( ret != 0) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_kernel_mem failed");
            goto out;
        }
    } else {
        ret = xc_dom_kernel_file(dom, info->u.pv.kernel.path);
        if ( ret != 0) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_kernel_file failed");
            goto out;
        }
    }

    if ( info->u.pv.ramdisk.path && strlen(info->u.pv.ramdisk.path) ) {
        if (info->u.pv.ramdisk.mapped) {
            if ( (ret = xc_dom_ramdisk_mem(dom, info->u.pv.ramdisk.data, info->u.pv.ramdisk.size)) != 0 ) {
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_ramdisk_mem failed");
                goto out;
            }
        } else {
            if ( (ret = xc_dom_ramdisk_file(dom, info->u.pv.ramdisk.path)) != 0 ) {
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_ramdisk_file failed");
                goto out;
            }
        }
    }

    dom->flags = flags;
    dom->console_evtchn = state->console_port;
    dom->console_domid = state->console_domid;
    dom->xenstore_evtchn = state->store_port;
    dom->xenstore_domid = state->store_domid;

    if ( (ret = xc_dom_boot_xen_init(dom, ctx->xch, domid)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_boot_xen_init failed");
        goto out;
    }
    if ( (ret = xc_dom_parse_image(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_parse_image failed");
        goto out;
    }
    if ( (ret = xc_dom_mem_init(dom, info->target_memkb / 1024)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_mem_init failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_mem_init(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_boot_mem_init failed");
        goto out;
    }
    if ( (ret = xc_dom_build_image(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_build_image failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_image(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_boot_image failed");
        goto out;
    }
    if ( (ret = xc_dom_gnttab_init(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_gnttab_init failed");
        goto out;
    }

    state->console_mfn = xc_dom_p2m_host(dom, dom->console_pfn);
    state->store_mfn = xc_dom_p2m_host(dom, dom->xenstore_pfn);

    ret = 0;
out:
    xc_dom_release(dom);
    return ret == 0 ? 0 : ERROR_FAIL;
}

static unsigned long timer_mode(const libxl_domain_build_info *info)
{
    const libxl_timer_mode mode = info->u.hvm.timer_mode;
    assert(mode != LIBXL_TIMER_MODE_DELAY_FOR_MISSED_TICKS &&
           mode <= LIBXL_TIMER_MODE_ONE_MISSED_TICK_PENDING);
    return ((unsigned long)mode);
}
static int hvm_build_set_params(xc_interface *handle, uint32_t domid,
                                libxl_domain_build_info *info,
                                int store_evtchn, unsigned long *store_mfn,
                                int console_evtchn, unsigned long *console_mfn,
                                domid_t store_domid, domid_t console_domid)
{
    struct hvm_info_table *va_hvm;
    uint8_t *va_map, sum;
    int i;

    va_map = xc_map_foreign_range(handle, domid,
                                  XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                  HVM_INFO_PFN);
    if (va_map == NULL)
        return -1;

    va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
    va_hvm->apic_mode = libxl_defbool_val(info->u.hvm.apic);
    va_hvm->nr_vcpus = info->max_vcpus;
    memcpy(va_hvm->vcpu_online, &info->cur_vcpus, sizeof(info->cur_vcpus));
    for (i = 0, sum = 0; i < va_hvm->length; i++)
        sum += ((uint8_t *) va_hvm)[i];
    va_hvm->checksum -= sum;
    munmap(va_map, XC_PAGE_SIZE);

    xc_get_hvm_param(handle, domid, HVM_PARAM_STORE_PFN, store_mfn);
    xc_get_hvm_param(handle, domid, HVM_PARAM_CONSOLE_PFN, console_mfn);
    xc_set_hvm_param(handle, domid, HVM_PARAM_PAE_ENABLED,
                     libxl_defbool_val(info->u.hvm.pae));
#if defined(__i386__) || defined(__x86_64__)
    xc_set_hvm_param(handle, domid, HVM_PARAM_VIRIDIAN,
                     libxl_defbool_val(info->u.hvm.viridian));
    xc_set_hvm_param(handle, domid, HVM_PARAM_HPET_ENABLED,
                     libxl_defbool_val(info->u.hvm.hpet));
#endif
    xc_set_hvm_param(handle, domid, HVM_PARAM_TIMER_MODE, timer_mode(info));
    xc_set_hvm_param(handle, domid, HVM_PARAM_VPT_ALIGN,
                     libxl_defbool_val(info->u.hvm.vpt_align));
    xc_set_hvm_param(handle, domid, HVM_PARAM_NESTEDHVM,
                     libxl_defbool_val(info->u.hvm.nested_hvm));
    xc_set_hvm_param(handle, domid, HVM_PARAM_STORE_EVTCHN, store_evtchn);
    xc_set_hvm_param(handle, domid, HVM_PARAM_CONSOLE_EVTCHN, console_evtchn);

    xc_dom_gnttab_hvm_seed(handle, domid, *console_mfn, *store_mfn, console_domid, store_domid);
    return 0;
}

static const char *libxl__domain_firmware(libxl__gc *gc,
                                          libxl_domain_build_info *info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *firmware;

    if (info->u.hvm.firmware)
        firmware = info->u.hvm.firmware;
    else {
        switch (info->device_model_version)
        {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            firmware = "hvmloader";
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            firmware = "hvmloader";
            break;
        default:
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "invalid device model version %d",
                       info->device_model_version);
            return NULL;
            break;
        }
    }
    return libxl__abs_path(gc, firmware, libxl__xenfirmwaredir_path());
}

int libxl__build_hvm(libxl__gc *gc, uint32_t domid,
              libxl_domain_build_info *info,
              libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int ret, rc = ERROR_FAIL;
    const char *firmware = libxl__domain_firmware(gc, info);

    if (!firmware)
        goto out;
    ret = xc_hvm_build_target_mem(
        ctx->xch,
        domid,
        (info->max_memkb - info->video_memkb) / 1024,
        (info->target_memkb - info->video_memkb) / 1024,
        firmware);
    if (ret) {
        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, ret, "hvm building failed");
        goto out;
    }
    ret = hvm_build_set_params(ctx->xch, domid, info, state->store_port,
                               &state->store_mfn, state->console_port,
                               &state->console_mfn, state->store_domid,
                               state->console_domid);
    if (ret) {
        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, ret, "hvm build set params failed");
        goto out;
    }
    rc = 0;
out:
    return rc;
}

int libxl__qemu_traditional_cmd(libxl__gc *gc, uint32_t domid,
                                const char *cmd)
{
    char *path = NULL;
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/command",
                          domid);
    return libxl__xs_write(gc, XBT_NULL, path, "%s", cmd);
}

int libxl__domain_restore_common(libxl__gc *gc, uint32_t domid,
                                 libxl_domain_build_info *info,
                                 libxl__domain_build_state *state,
                                 int fd)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    /* read signature */
    int rc;
    int hvm, pae, superpages;
    int no_incr_generationid;
    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        hvm = 1;
        superpages = 1;
        pae = libxl_defbool_val(info->u.hvm.pae);
        no_incr_generationid = !libxl_defbool_val(info->u.hvm.incr_generationid);
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        hvm = 0;
        superpages = 0;
        pae = 1;
        no_incr_generationid = 0;
        break;
    default:
        return ERROR_INVAL;
    }
    rc = xc_domain_restore(ctx->xch, fd, domid,
                           state->store_port, &state->store_mfn,
                           state->store_domid, state->console_port,
                           &state->console_mfn, state->console_domid,
                           hvm, pae, superpages, no_incr_generationid,
                           &state->vm_generationid_addr);
    if ( rc ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "restoring domain");
        return ERROR_FAIL;
    }
    return 0;
}

struct suspendinfo {
    libxl__gc *gc;
    xc_evtchn *xce; /* event channel handle */
    int suspend_eventchn;
    int domid;
    int hvm;
    unsigned int flags;
    int guest_responded;
};

static int libxl__domain_suspend_common_switch_qemu_logdirty(int domid, unsigned int enable, void *data)
{
    struct suspendinfo *si = data;
    libxl_ctx *ctx = libxl__gc_owner(si->gc);
    char *path;
    bool rc;

    path = libxl__sprintf(si->gc, "/local/domain/0/device-model/%u/logdirty/cmd", domid);
    if (!path)
        return 1;

    if (enable)
        rc = xs_write(ctx->xsh, XBT_NULL, path, "enable", strlen("enable"));
    else
        rc = xs_write(ctx->xsh, XBT_NULL, path, "disable", strlen("disable"));

    return rc ? 0 : 1;
}

static int libxl__domain_suspend_common_callback(void *data)
{
    struct suspendinfo *si = data;
    unsigned long hvm_s_state = 0, hvm_pvdrv = 0;
    int ret;
    char *state = "suspend";
    int watchdog;
    libxl_ctx *ctx = libxl__gc_owner(si->gc);
    xs_transaction_t t;

    if (si->hvm) {
        xc_get_hvm_param(ctx->xch, si->domid, HVM_PARAM_CALLBACK_IRQ, &hvm_pvdrv);
        xc_get_hvm_param(ctx->xch, si->domid, HVM_PARAM_ACPI_S_STATE, &hvm_s_state);
    }

    if ((hvm_s_state == 0) && (si->suspend_eventchn >= 0)) {
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "issuing %s suspend request via event channel",
                   si->hvm ? "PVHVM" : "PV");
        ret = xc_evtchn_notify(si->xce, si->suspend_eventchn);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "xc_evtchn_notify failed ret=%d", ret);
            return 0;
        }
        ret = xc_await_suspend(ctx->xch, si->xce, si->suspend_eventchn);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "xc_await_suspend failed ret=%d", ret);
            return 0;
        }
        si->guest_responded = 1;
        return 1;
    }

    if (si->hvm && (!hvm_pvdrv || hvm_s_state)) {
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Calling xc_domain_shutdown on HVM domain");
        xc_domain_shutdown(ctx->xch, si->domid, SHUTDOWN_suspend);
        /* The guest does not (need to) respond to this sort of request. */
        si->guest_responded = 1;
    } else {
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "issuing %s suspend request via XenBus control node",
                   si->hvm ? "PVHVM" : "PV");

        libxl__domain_pvcontrol_write(si->gc, XBT_NULL, si->domid, "suspend");

        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "wait for the guest to acknowledge suspend request");
        watchdog = 60;
        while (!strcmp(state, "suspend") && watchdog > 0) {
            usleep(100000);

            state = libxl__domain_pvcontrol_read(si->gc, XBT_NULL, si->domid);
            if (!state) state = "";

            watchdog--;
        }

        /*
         * Guest appears to not be responding. Cancel the suspend
         * request.
         *
         * We re-read the suspend node and clear it within a
         * transaction in order to handle the case where we race
         * against the guest catching up and acknowledging the request
         * at the last minute.
         */
        if (!strcmp(state, "suspend")) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "guest didn't acknowledge suspend, cancelling request");
        retry_transaction:
            t = xs_transaction_start(ctx->xsh);

            state = libxl__domain_pvcontrol_read(si->gc, t, si->domid);
            if (!state) state = "";

            if (!strcmp(state, "suspend"))
                libxl__domain_pvcontrol_write(si->gc, t, si->domid, "");

            if (!xs_transaction_end(ctx->xsh, t, 0))
                if (errno == EAGAIN)
                    goto retry_transaction;

        }

        /*
         * Final check for guest acknowledgement. The guest may have
         * acknowledged while we were cancelling the request in which
         * case we lost the race while cancelling and should continue.
         */
        if (!strcmp(state, "suspend")) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "guest didn't acknowledge suspend, request cancelled");
            return 0;
        }

        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "guest acknowledged suspend request");
        si->guest_responded = 1;
    }

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "wait for the guest to suspend");
    watchdog = 60;
    while (watchdog > 0) {
        xc_domaininfo_t info;

        usleep(100000);
        ret = xc_domain_getinfolist(ctx->xch, si->domid, 1, &info);
        if (ret == 1 && info.domain == si->domid && info.flags & XEN_DOMINF_shutdown) {
            int shutdown_reason;

            shutdown_reason = (info.flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask;
            if (shutdown_reason == SHUTDOWN_suspend) {
                LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "guest has suspended");
                return 1;
            }
        }

        watchdog--;
    }

    LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "guest did not suspend");
    return 0;
}

int libxl__domain_suspend_common(libxl__gc *gc, uint32_t domid, int fd,
                                 libxl_domain_type type,
                                 int live, int debug)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int flags;
    int port;
    struct save_callbacks callbacks;
    struct suspendinfo si;
    int hvm, rc = ERROR_FAIL;
    unsigned long vm_generationid_addr;

    switch (type) {
    case LIBXL_DOMAIN_TYPE_HVM: {
        char *path;
        char *addr;

        path = libxl__sprintf(gc, "%s/hvmloader/generation-id-address",
                              libxl__xs_get_dompath(gc, domid));
        addr = libxl__xs_read(gc, XBT_NULL, path);

        vm_generationid_addr = (addr) ? strtoul(addr, NULL, 0) : 0;
        hvm = 1;
        break;
    }
    case LIBXL_DOMAIN_TYPE_PV:
        vm_generationid_addr = 0;
        hvm = 0;
        break;
    default:
        return ERROR_INVAL;
    }

    flags = (live) ? XCFLAGS_LIVE : 0
          | (debug) ? XCFLAGS_DEBUG : 0
          | (hvm) ? XCFLAGS_HVM : 0;

    si.domid = domid;
    si.flags = flags;
    si.hvm = hvm;
    si.gc = gc;
    si.suspend_eventchn = -1;
    si.guest_responded = 0;

    si.xce = xc_evtchn_open(NULL, 0);
    if (si.xce == NULL)
        goto out;
    else
    {
        port = xs_suspend_evtchn_port(si.domid);

        if (port >= 0) {
            si.suspend_eventchn = xc_suspend_evtchn_init(ctx->xch, si.xce, si.domid, port);

            if (si.suspend_eventchn < 0)
                LIBXL__LOG(ctx, LIBXL__LOG_WARNING, "Suspend event channel initialization failed");
        }
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.suspend = libxl__domain_suspend_common_callback;
    callbacks.switch_qemu_logdirty = libxl__domain_suspend_common_switch_qemu_logdirty;
    callbacks.data = &si;

    rc = xc_domain_save(ctx->xch, fd, domid, 0, 0, flags, &callbacks,
                        hvm, vm_generationid_addr);
    if ( rc ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "saving domain: %s",
                         si.guest_responded ?
                         "domain responded to suspend request" :
                         "domain did not respond to suspend request");
        if ( !si.guest_responded )
            rc = ERROR_GUEST_TIMEDOUT;
        else
            rc = ERROR_FAIL;
    }

    if (si.suspend_eventchn > 0)
        xc_suspend_evtchn_release(ctx->xch, si.xce, domid, si.suspend_eventchn);
    if (si.xce != NULL)
        xc_evtchn_close(si.xce);

out:
    return rc;
}

int libxl__domain_save_device_model(libxl__gc *gc, uint32_t domid, int fd)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int ret, fd2 = -1, c;
    char buf[1024];
    const char *filename = libxl__device_model_savefile(gc, domid);
    struct stat st;
    uint32_t qemu_state_len;

    switch (libxl__device_model_version_running(gc, domid)) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL: {
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG,
                   "Saving device model state to %s", filename);
        libxl__qemu_traditional_cmd(gc, domid, "save");
        libxl__wait_for_device_model(gc, domid, "paused", NULL, NULL, NULL);
        break;
    }
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        fd2 = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd2 < 0) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                             "Unable to create a QEMU save file\n");
            return ERROR_FAIL;
        }
        /* Save DM state into fd2 */
        ret = libxl__qmp_migrate(gc, domid, fd2);
        if (ret)
            goto out;
        close(fd2);
        fd2 = -1;
        break;
    default:
        return ERROR_INVAL;
    }

    if (stat(filename, &st) < 0)
    {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Unable to stat qemu save file\n");
        ret = ERROR_FAIL;
        goto out;
    }

    qemu_state_len = st.st_size;
    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Qemu state is %d bytes\n", qemu_state_len);

    ret = libxl_write_exactly(ctx, fd, QEMU_SIGNATURE, strlen(QEMU_SIGNATURE),
                              "saved-state file", "qemu signature");
    if (ret)
        goto out;

    ret = libxl_write_exactly(ctx, fd, &qemu_state_len, sizeof(qemu_state_len),
                            "saved-state file", "saved-state length");
    if (ret)
        goto out;

    fd2 = open(filename, O_RDONLY);
    if (fd2 < 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Unable to open qemu save file\n");
        goto out;
    }
    while ((c = read(fd2, buf, sizeof(buf))) != 0) {
        if (c < 0) {
            if (errno == EINTR)
                continue;
            ret = errno;
            goto out;
        }
        ret = libxl_write_exactly(
            ctx, fd, buf, c, "saved-state file", "qemu state");
        if (ret)
            goto out;
    }
    ret = 0;
out:
    if (fd2 >= 0) close(fd2);
    unlink(filename);
    return ret;
}

char *libxl__uuid2string(libxl__gc *gc, const libxl_uuid uuid)
{
    char *s = libxl__sprintf(gc, LIBXL_UUID_FMT, LIBXL_UUID_BYTES(uuid));
    if (!s)
        LIBXL__LOG(libxl__gc_owner(gc), LIBXL__LOG_ERROR, "cannot allocate for uuid");
    return s;
}

static const char *userdata_path(libxl__gc *gc, uint32_t domid,
                                      const char *userdata_userid,
                                      const char *wh)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path, *uuid_string;
    libxl_dominfo info;
    int rc;

    rc = libxl_domain_info(ctx, &info, domid);
    if (rc) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to find domain info"
                     " for domain %"PRIu32, domid);
        return NULL;
    }
    uuid_string = libxl__sprintf(gc, LIBXL_UUID_FMT, LIBXL_UUID_BYTES(info.uuid));

    path = libxl__sprintf(gc, "/var/lib/xen/"
                         "userdata-%s.%u.%s.%s",
                         wh, domid, uuid_string, userdata_userid);
    if (!path)
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to allocate for"
                     " userdata path");
    return path;
}

static int userdata_delete(libxl__gc *gc, const char *path)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int r;
    r = unlink(path);
    if (r) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "remove failed for %s", path);
        return errno;
    }
    return 0;
}

void libxl__userdata_destroyall(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *pattern;
    glob_t gl;
    int r, i;

    pattern = userdata_path(gc, domid, "*", "?");
    if (!pattern)
        goto out;

    gl.gl_pathc = 0;
    gl.gl_pathv = 0;
    gl.gl_offs = 0;
    r = glob(pattern, GLOB_ERR|GLOB_NOSORT|GLOB_MARK, 0, &gl);
    if (r == GLOB_NOMATCH)
        goto out;
    if (r)
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "glob failed for %s", pattern);

    for (i=0; i<gl.gl_pathc; i++) {
        userdata_delete(gc, gl.gl_pathv[i]);
    }
    globfree(&gl);
out:
    return;
}

int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen)
{
    GC_INIT(ctx);
    const char *filename;
    const char *newfilename;
    int e, rc;
    int fd = -1;
    FILE *f = NULL;
    size_t rs;

    filename = userdata_path(gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    if (!datalen) {
        rc = userdata_delete(gc, filename);
        goto out;
    }

    newfilename = userdata_path(gc, domid, userdata_userid, "n");
    if (!newfilename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    rc = ERROR_FAIL;

    fd= open(newfilename, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd<0)
        goto err;

    f= fdopen(fd, "wb");
    if (!f)
        goto err;
    fd = -1;

    rs = fwrite(data, 1, datalen, f);
    if (rs != datalen) {
        assert(ferror(f));
        goto err;
    }

    if (fclose(f))
        goto err;
    f = 0;

    if (rename(newfilename,filename))
        goto err;

    rc = 0;

err:
    e = errno;
    if (f) fclose(f);
    if (fd>=0) close(fd);

    errno = e;
    if ( rc )
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "cannot write %s for %s",
                 newfilename, filename);
out:
    GC_FREE;
    return rc;
}

int libxl_userdata_retrieve(libxl_ctx *ctx, uint32_t domid,
                                 const char *userdata_userid,
                                 uint8_t **data_r, int *datalen_r)
{
    GC_INIT(ctx);
    const char *filename;
    int e, rc;
    int datalen = 0;
    void *data = 0;

    filename = userdata_path(gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    e = libxl_read_file_contents(ctx, filename, data_r ? &data : 0, &datalen);
    if (e && errno != ENOENT) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (!e && !datalen) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "userdata file %s is empty", filename);
        if (data_r) assert(!*data_r);
        rc = ERROR_FAIL;
        goto out;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;
    rc = 0;
out:
    GC_FREE;
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
