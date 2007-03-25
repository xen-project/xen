/*
 * Copyright (c) 2006-2007 XenSource, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <curl/curl.h>

#include "xen_host.h"
#include "xen_sr.h"
#include "xen_vbd.h"
#include "xen_vdi.h"
#include "xen_console.h"
#include "xen_vm.h"
#include "xen_vm_metrics.h"


static void usage()
{
    fprintf(stderr,
"Usage:\n"
"\n"
"    test_bindings <url> <username> <password>\n"
"\n"
"where\n"
"        <url>      is a fragment of the server's URL, e.g. localhost:8005/RPC2;\n"
"        <username> is the username to use at the server; and\n"
"        <password> is the password.\n");

    exit(EXIT_FAILURE);
}


static char *url;


typedef struct
{
    xen_result_func func;
    void *handle;
} xen_comms;


static xen_vm create_new_vm(xen_session *session, bool hvm);
static void print_session_info(xen_session *session);
static void print_vm_power_state(xen_session *session, xen_vm vm);
static void print_vm_metrics(xen_session *session, xen_vm vm);


static size_t
write_func(void *ptr, size_t size, size_t nmemb, xen_comms *comms)
{
    size_t n = size * nmemb;
    return comms->func(ptr, n, comms->handle) ? n : 0;
}


static int
call_func(const void *data, size_t len, void *user_handle,
          void *result_handle, xen_result_func result_func)
{
    (void)user_handle;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    xen_comms comms = {
        .func = result_func,
        .handle = result_handle
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_MUTE, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &comms);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);

    CURLcode result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    return result;
}


static void print_error(xen_session *session)
{
    fprintf(stderr, "Error: %d", session->error_description_count);
    for (int i = 0; i < session->error_description_count; i++)
    {
        fprintf(stderr, "%s ", session->error_description[i]);
    }
    fprintf(stderr, "\n");
}


int main(int argc, char **argv)
{
    if (argc != 4)
    {
        usage();
    }

    url = argv[1];
    char *username = argv[2];
    char *password = argv[3];

    xmlInitParser();
    xen_init();
    curl_global_init(CURL_GLOBAL_ALL);

#define CLEANUP                                 \
    do {                                        \
        xen_session_logout(session);            \
        curl_global_cleanup();                  \
        xen_fini();                             \
        xmlCleanupParser();                     \
    } while(0)                                  \

    
    xen_session *session =
        xen_session_login_with_password(call_func, NULL, username, password);

    print_session_info(session);
    if (!session->ok)
    {
        /* Error has been logged, just clean up. */
        CLEANUP;
        return 1;
    }

    xen_vm vm;
    if (!xen_vm_get_by_uuid(session, &vm,
                            "00000000-0000-0000-0000-000000000000"))
    {
        print_error(session);
        CLEANUP;
        return 1;
    }

    char *vm_uuid;
    if (!xen_vm_get_uuid(session, &vm_uuid, vm))
    {
        print_error(session);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    char *vm_uuid_bytes;
    if (!xen_uuid_string_to_bytes(vm_uuid, &vm_uuid_bytes))
    {
        fprintf(stderr, "xen_uuid_string_to_bytes failed.\n");
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_vm_record *vm_record;
    if (!xen_vm_get_record(session, &vm_record, vm))
    {
        print_error(session);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_host host;
    if (!xen_session_get_this_host(session, &host, session))
    {
        print_error(session);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_string_string_map *versions;
    if (!xen_host_get_software_version(session, &versions, host))
    {
        print_error(session);
        xen_host_free(host);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    char *dmesg;
    if (!xen_host_dmesg(session, &dmesg, host))
    {
        print_error(session);
        xen_string_string_map_free(versions);
        xen_host_free(host);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_string_set *supported_bootloaders;
    if (!xen_host_get_supported_bootloaders(session, &supported_bootloaders,
                                            host))
    {
        print_error(session);
        free(dmesg);
        xen_string_string_map_free(versions);
        xen_host_free(host);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_string_set *capabilities;
    if (!xen_host_get_capabilities(session, &capabilities, host))
    {
        print_error(session);
        free(dmesg);
        xen_string_set_free(supported_bootloaders);
        xen_string_string_map_free(versions);
        xen_host_free(host);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    printf("%s.\n", vm_uuid);

    fprintf(stderr, "In bytes, the VM UUID is ");
    for (int i = 0; i < 15; i++)
    {
        fprintf(stderr, "%x, ", (unsigned int)vm_uuid_bytes[i]);
    }
    fprintf(stderr, "%x.\n", (unsigned int)vm_uuid_bytes[15]);

    printf("%zd.\n", versions->size);

    for (size_t i = 0; i < versions->size; i++)
    {
        printf("%s -> %s.\n", versions->contents[i].key,
               versions->contents[i].val);
    }

    printf("Host dmesg follows:\n%s\n\n", dmesg);

    printf("Host supports the following bootloaders:");
    for (size_t i = 0; i < supported_bootloaders->size; i++)
    {
        printf(" %s", supported_bootloaders->contents[i]);
    }
    printf("\n");

    printf("Host has the following capabilities:");
    for (size_t i = 0; i < capabilities->size; i++)
    {
        printf(" %s", capabilities->contents[i]);
    }
    printf("\n");

    printf("%s.\n", vm_record->uuid);

    printf("Resident on %s.\n", (char *)vm_record->resident_on->u.handle);

    printf("%s.\n", xen_vm_power_state_to_string(vm_record->power_state));

    xen_uuid_bytes_free(vm_uuid_bytes);
    xen_uuid_free(vm_uuid);

    xen_vm_record_free(vm_record);

    xen_host_free(host);
    xen_string_string_map_free(versions);
    free(dmesg);
    xen_string_set_free(supported_bootloaders);
    xen_string_set_free(capabilities);

    print_vm_metrics(session, vm);
    if (!session->ok)
    {
        /* Error has been logged, just clean up. */
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_vm_free(vm);

    xen_vm new_vm = create_new_vm(session, true);
    if (!session->ok)
    {
        /* Error has been logged, just clean up. */
        CLEANUP;
        return 1;
    }

    print_vm_power_state(session, new_vm);
    if (!session->ok)
    {
        /* Error has been logged, just clean up. */
        xen_vm_free(new_vm);
        CLEANUP;
        return 1;
    }

    xen_vm_free(new_vm);
    CLEANUP;

    return 0;
}


/**
 * Creation of a new VM, using the Named Parameters idiom.  Allocate the
 * xen_vm_record here, but the sets through the library.  Either
 * allocation patterns can be used, as long as the allocation and free are
 * paired correctly.
 */
static xen_vm create_new_vm(xen_session *session, bool hvm)
{
    xen_string_string_map *vcpus_params = xen_string_string_map_alloc(1);
    vcpus_params->contents[0].key = strdup("weight");
    vcpus_params->contents[0].val = strdup("300");

    xen_string_string_map *hvm_boot_params;
    if (hvm)
    {
        hvm_boot_params = xen_string_string_map_alloc(1);
        hvm_boot_params->contents[0].key = strdup("order");
        hvm_boot_params->contents[0].val = strdup("cd");
    }
    else
    {
        hvm_boot_params = NULL;
    }

    xen_vm_record vm_record =
        {
            .name_label = hvm ? "NewHVM" : "NewPV",
            .name_description = hvm ? "New HVM VM" : "New PV VM",
            .user_version = 1,
            .is_a_template = false,
            .memory_static_max = 256,
            .memory_dynamic_max = 256,
            .memory_dynamic_min = 128,
            .memory_static_min = 128,
            .vcpus_params = vcpus_params,
            .vcpus_max = 4,
            .vcpus_at_startup = 2,
            .actions_after_shutdown = XEN_ON_NORMAL_EXIT_DESTROY,
            .actions_after_reboot = XEN_ON_NORMAL_EXIT_RESTART,
            .actions_after_crash = XEN_ON_CRASH_BEHAVIOUR_PRESERVE,
            .hvm_boot_policy = hvm ? "BIOS order" : NULL,
            .hvm_boot_params = hvm ? hvm_boot_params : NULL,
            .pv_bootloader   = hvm ? NULL : "pygrub",
            .pv_kernel       = hvm ? NULL : "/boot/vmlinuz-2.6.16.33-xen",
        };

    xen_vm vm;
    xen_vm_create(session, &vm, &vm_record);

    xen_string_string_map_free(vcpus_params);
    xen_string_string_map_free(hvm_boot_params);

    if (!session->ok)
    {
        fprintf(stderr, "VM creation failed.\n");
        print_error(session);
        return NULL;
    }


    /*
     * Create a new disk for the new VM.
     */
    xen_sr_set *srs;
    if (!xen_sr_get_by_name_label(session, &srs, "QCoW") ||
        srs->size < 1)
    {
        fprintf(stderr, "SR lookup failed.\n");
        print_error(session);
        xen_vm_free(vm);
        return NULL;
    }

    xen_sr_record_opt sr_record =
        {
            .u.handle = srs->contents[0]
        };
    xen_vdi_record vdi0_record =
        {
            .name_label = "MyRootFS",
            .name_description = "MyRootFS description",
            .sr = &sr_record,
            .virtual_size = (INT64_C(1) << 30),  // 1GiB
            .type = XEN_VDI_TYPE_SYSTEM,
            .sharable = false,
            .read_only = false
        };
    
    xen_vdi vdi0;
    if (!xen_vdi_create(session, &vdi0, &vdi0_record))
    {
        fprintf(stderr, "VDI creation failed.\n");
        print_error(session);

        xen_sr_set_free(srs);
        xen_vm_free(vm);
        return NULL;
    }


    xen_vm_record_opt vm_record_opt =
        {
            .u.handle = vm
        };
    xen_vdi_record_opt vdi0_record_opt =
        {
            .u.handle = vdi0
        };
    xen_vbd_record vbd0_record =
        {
            .vm = &vm_record_opt,
            .vdi = &vdi0_record_opt,
            .device = "xvda1",
            .mode = XEN_VBD_MODE_RW,
            .bootable = 1,
        };

    xen_vbd vbd0;
    if (!xen_vbd_create(session, &vbd0, &vbd0_record))
    {
        fprintf(stderr, "VBD creation failed.\n");
        print_error(session);

        xen_vdi_free(vdi0);
        xen_sr_set_free(srs);
        xen_vm_free(vm);
        return NULL;
    }

    xen_console vnc_console = NULL;
    if (hvm) {
        xen_console_record vnc_console_record =
            {
                .protocol = XEN_CONSOLE_PROTOCOL_RFB,
                .vm = &vm_record_opt,
            };

        if (!xen_console_create(session, &vnc_console, &vnc_console_record))
        {
            fprintf(stderr, "VNC console creation failed.\n");
            print_error(session);

            xen_vbd_free(vbd0);
            xen_vdi_free(vdi0);
            xen_sr_set_free(srs);
            xen_vm_free(vm);
            return NULL;
        }
    }

    char *vm_uuid;
    char *vdi0_uuid;
    char *vbd0_uuid;
    char *vnc_uuid = NULL;

    xen_vm_get_uuid(session,  &vm_uuid,   vm);
    xen_vdi_get_uuid(session, &vdi0_uuid, vdi0);
    xen_vbd_get_uuid(session, &vbd0_uuid, vbd0); 
    if (hvm) {
        xen_console_get_uuid(session, &vnc_uuid, vnc_console);
    }

    if (!session->ok)
    {
        fprintf(stderr, "get_uuid call failed.\n");
        print_error(session);

        xen_uuid_free(vm_uuid);
        xen_uuid_free(vdi0_uuid);
        xen_uuid_free(vbd0_uuid);
        xen_uuid_free(vnc_uuid);
        xen_vbd_free(vbd0);
        xen_vdi_free(vdi0);
        xen_console_free(vnc_console);
        xen_sr_set_free(srs);
        xen_vm_free(vm);
        return NULL;
    }

    if (hvm) {
        fprintf(stderr,
                "Created a new HVM VM, with UUID %s, VDI UUID %s, VBD "
                "UUID %s, and VNC console UUID %s.\n",
                vm_uuid, vdi0_uuid, vbd0_uuid, vnc_uuid);
    }
    else {
        fprintf(stderr,
                "Created a new PV VM, with UUID %s, VDI UUID %s, and VBD "
                "UUID %s.\n",
                vm_uuid, vdi0_uuid, vbd0_uuid);
    }

    xen_uuid_free(vm_uuid);
    xen_uuid_free(vdi0_uuid);
    xen_uuid_free(vbd0_uuid);
    xen_uuid_free(vnc_uuid);
    xen_vbd_free(vbd0);
    xen_vdi_free(vdi0);
    xen_console_free(vnc_console);
    xen_sr_set_free(srs);

    return vm;
}


/**
 * Print the power state for the given VM.
 */
static void print_vm_power_state(xen_session *session, xen_vm vm)
{
    char *vm_uuid;
    enum xen_vm_power_state power_state;

    if (!xen_vm_get_uuid(session, &vm_uuid, vm))
    {
        print_error(session);
        return;
    }

    if (!xen_vm_get_power_state(session, &power_state, vm))
    {
        xen_uuid_free(vm_uuid);
        print_error(session);
        return;
    }

    printf("VM %s power state is %s.\n", vm_uuid,
           xen_vm_power_state_to_string(power_state));

    xen_uuid_free(vm_uuid);
}


/**
 * Workaround for whinging GCCs, as suggested by strftime(3).
 */
static size_t my_strftime(char *s, size_t max, const char *fmt,
                          const struct tm *tm)
{
    return strftime(s, max, fmt, tm);
}


/**
 * Print some session details.
 */
static void print_session_info(xen_session *session)
{
    xen_session_record *record;
    if (!xen_session_get_record(session, &record, session))
    {
        print_error(session);
        return;
    }

    printf("Session UUID: %s.\n", record->uuid);
    printf("Session user: %s.\n", record->this_user);
    char time[256];
    struct tm *tm = localtime(&record->last_active);
    my_strftime(time, 256, "Session last active: %c, local time.\n", tm);
    printf(time);

    char *uuid = NULL;
    char *this_user = NULL;
    xen_session_get_uuid(session, &uuid, session);
    xen_session_get_this_user(session, &this_user, session);

    if (!session->ok)
    {
        xen_session_record_free(record);
        print_error(session);
        return;
    }

    assert(!strcmp(record->uuid, uuid));
    assert(!strcmp(record->this_user, this_user));

    xen_session_record_free(record);
}


/**
 * Print the metrics for the given VM.
 */
static void print_vm_metrics(xen_session *session, xen_vm vm)
{
    xen_vm_metrics vm_metrics;
    if (!xen_vm_get_metrics(session, &vm_metrics, vm))
    {
        print_error(session);
        return;
    }

    xen_vm_metrics_record *vm_metrics_record;
    if (!xen_vm_metrics_get_record(session, &vm_metrics_record, vm_metrics))
    {
        xen_vm_metrics_free(vm_metrics);
        print_error(session);
        return;
    }

    char time[256];
    struct tm *tm = localtime(&vm_metrics_record->last_updated);
    my_strftime(time, 256, "Metrics updated at %c, local time.\n", tm);
    printf(time);

    for (size_t i = 0; i < vm_metrics_record->vcpus_utilisation->size; i++)
    {
        printf("%"PRId64" -> %lf.\n",
               vm_metrics_record->vcpus_utilisation->contents[i].key,
               vm_metrics_record->vcpus_utilisation->contents[i].val);
    }

    xen_vm_metrics_record_free(vm_metrics_record);
    xen_vm_metrics_free(vm_metrics);
}
