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
#include <xen/api/xen_all.h>

//#define PRINT_XML
//////////////#define POOL_TESTS

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
static void print_methods(xen_session *session);
static void print_vm_power_state(xen_session *session, xen_vm vm);
static void print_vm_metrics(xen_session *session, xen_vm vm);


static size_t
write_func(void *ptr, size_t size, size_t nmemb, xen_comms *comms)
{
    size_t n = size * nmemb;
#ifdef PRINT_XML
    printf("\n\n---Result from server -----------------------\n");
    printf("%s\n",((char*) ptr));
    fflush(stdout);
#endif
    return comms->func(ptr, n, comms->handle) ? n : 0;
}


static int
call_func(const void *data, size_t len, void *user_handle,
          void *result_handle, xen_result_func result_func)
{
    (void)user_handle;

#ifdef PRINT_XML
    printf("\n\n---Data to server: -----------------------\n");
    printf("%s\n",((char*) data));
    fflush(stdout);
#endif

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


#ifdef POOL_TESTS
#define NAME_DESCRIPTION "TestPool"
#define NAME_DESCRIPTION_2 "TestPool-2"
#define NAME_LABEL "Pool-1"
#define NAME_LABEL_2 "Pool-2"
#define SCHED_NAME "credit"
#define NCPU_VAL   2
#define NCPU_VAL_2   1


static int pool_tests(xen_session *session, xen_host host)
{
    int rc = 1;
    xen_cpu_pool_set            *pools = NULL;
    xen_host_record             *host_record = NULL;
    xen_cpu_pool_record_opt     *cpu_pool_opt = NULL;
    xen_cpu_pool_record         *cpu_pool_rec = NULL;
    xen_host_cpu_set            *host_cpu_set = NULL;
    xen_host_cpu_record         *host_cpu_record = NULL;
    xen_vm_set                  *vm_set = NULL;
    xen_cpu_pool                pool = NULL;
    xen_cpu_pool                pool_out = NULL;
    xen_string_string_map       *pool_other_config = NULL;
    xen_vm_record               *vm_record = NULL;
    xen_string_set              *proposed_cpus = NULL;
    xen_host                    res_host = NULL;
    char                        *name_description = NULL;
    char                        *name_label = NULL;
    char                        *sched_policy = NULL;
    char                        *pool_uuid = NULL;
    int64_t                     ncpu;

    for (int loop= 0; loop < 1; loop++)
    {
        // Test extensions of class host
        printf("Test cpu_pool extension of host class -----------------------------------------\n");

        printf("host.get_resident_cpu_pools\n");
        if (!xen_host_get_resident_cpu_pools(session, &pools, host))
        {
            break;
        }
        if (pools->size != 1)
        {
            printf("Wrong pool count; only one pool expected\n");
            break;
        }
        printf("Pool UUID %s\n", (char*)pools->contents[0]);
        xen_cpu_pool_set_free(pools);
        pools = NULL;

        printf("host.get_record\n");
        if (!xen_host_get_record(session, &host_record, host))
        {
            break;
        }
        printf("Pool count %d\n", (int)host_record->resident_cpu_pools->size);
        if (host_record->resident_cpu_pools->size != 1)
        {
            break;
        }
        cpu_pool_opt = host_record->resident_cpu_pools->contents[0];
        printf("Pool UUID %s\n", (char*)cpu_pool_opt->u.handle);
        xen_host_record_free(host_record);
        host_record = NULL;
        cpu_pool_opt = NULL;


        // Test extensions of class host_cpu
        printf("host_cpu.get_all\n");
        if (!xen_host_cpu_get_all(session, &host_cpu_set))
        {
            break;
        }

        printf("host_cpu.get_cpu_pool & host_cpu.get_record\n");
        for (int i= 0; i < host_cpu_set->size; i++)
        {
            if (!xen_host_cpu_get_cpu_pool(session, &pools, host_cpu_set->contents[i]))
            {
                break;
            }
            if (pools->size > 1)
            {
                printf("Wrong pool count (xen_host_cpu_get_cpu_pool)\n");
                break;
            }

            printf("host_cpu (get_cpu_pool) %s, cpu_pool %s\n", (char*)host_cpu_set->contents[i],
                pools->size != 0 ? (char*)pools->contents[0] : "(None)");

            if (!xen_host_cpu_get_record(session, &host_cpu_record, host_cpu_set->contents[i]))
            {
                break;
            }
            if (host_cpu_record->cpu_pools->size > 1)
            {
                printf("Wrong pool count (xen_host_cpu_get_record)\n");
                break;
            }

            printf("host_cpu (get_record) %s, cpu_pool %s\n", (char*)host_cpu_set->contents[i],
                host_cpu_record->cpu_pools->size != 0
                ? (char*)((xen_cpu_pool_record_opt*)(host_cpu_record->cpu_pools->contents[0])->u.handle)
                : "(None)");

        }
        xen_host_cpu_record_free(host_cpu_record);
        host_cpu_record = NULL;
        xen_host_cpu_set_free(host_cpu_set);
        host_cpu_set = NULL;
        xen_cpu_pool_set_free(pools);
        pools = NULL;

        printf("host_cpu.get_unassigned_cpus\n");
        if (!xen_host_cpu_get_unassigned_cpus(session, &host_cpu_set))
        {
            break;
        }
        printf("Free cpus (not bound to a pool)\n");
        for (int i= 0; i < host_cpu_set->size; i++)
        {
            printf("  cpu UUID %s\n", (char*)host_cpu_set->contents[i]);
        }
        xen_host_cpu_set_free(host_cpu_set);
        host_cpu_set = NULL;


        printf("vm.get_record\n");
        if (!xen_vm_get_all(session, &vm_set))
        {
            break;
        }

        if (!xen_vm_get_record(session, &vm_record, vm_set->contents[0]))
        {
            break;
        }
        printf("VM %s, pool_name %s, cpu_pool %s\n", (char*)vm_set->contents[0],
            vm_record->pool_name, (char*)vm_record->cpu_pool->contents[0]);

        xen_vm_record_free(vm_record);
        vm_record = NULL;

        printf("vm.get_cpu_pool\n");
        if (!xen_vm_get_cpu_pool(session, &pools, vm_set->contents[0]))
        {
            break;
        }
        printf("vm_get_cpu_pool %s\n", (char*)pools->contents[0]);

        xen_vm_set_free(vm_set);
        xen_cpu_pool_set_free(pools);
        vm_set = NULL;
        pools = NULL;


        // Class cpu_pool

        // create
        pool_other_config = xen_string_string_map_alloc(1);
        pool_other_config->contents[0].key = strdup("type");
        pool_other_config->contents[0].val = strdup("bs2000");
        xen_string_set *proposed_CPUs_set = xen_string_set_alloc(1);
        proposed_CPUs_set->contents[0] = strdup("3");

        xen_cpu_pool_record new_cpu_pool_record =
        {
            .name_label = NAME_LABEL,
            .name_description = NAME_DESCRIPTION,
            .auto_power_on = false,
            .ncpu = NCPU_VAL,
            .sched_policy = SCHED_NAME,
            .proposed_cpus = proposed_CPUs_set,
            .other_config = pool_other_config,
        };

        printf("cpu_pool.create\n");
        if (!xen_cpu_pool_create(session, &pool, &new_cpu_pool_record))
        {
            break;
        }
        printf("New Pool UUID %s\n", (char*)pool);
        xen_string_set_free(proposed_CPUs_set);
        proposed_CPUs_set = NULL;
        xen_string_string_map_free(pool_other_config);
        pool_other_config = NULL;

        // get_by_name_label
        printf("cpu_pool.get_by_name_label\n");
        if (!xen_cpu_pool_get_by_name_label(session, &pools, "Pool-1"))
        {
            break;
        }
        if (strcmp((char*)pools->contents[0], (char*)pool) != 0)
        {
            break;
        }
        xen_cpu_pool_set_free(pools);
        pools = NULL;


        // get_by_uuid
        printf("cpu_pool.get_by_uuid\n");
        if (!xen_cpu_pool_get_by_uuid(session, &pool_out, pool))
        {
            break;
        }
        if (strcmp((char*)pool_out, (char*)pool) != 0)
        {
            printf("Wrong pool returned\n");
            break;
        }
        xen_cpu_pool_free(pool_out);
        pool_out = NULL;

        // get_all
        printf("cpu_pool.get_all\n");
        if (!xen_cpu_pool_get_all(session, &pools))
        {
            break;
        }
        if (pools->size != 2)
        {
            printf("Wrong pool count (%d)\n", (int)pools->size);
            break;
        }
        xen_cpu_pool_set_free(pools);
        pools = NULL;


        // get_activated
        printf("cpu_pool.get_activated\n");
        bool activated_state = true;
        if (!xen_cpu_pool_get_activated(session, &activated_state, pool))
        {
            break;
        }
        if (activated_state)
        {
            printf("Pool must not be activated\n");
            break;
        }


        // get_auto_power_on
        printf("cpu_pool.get_auto_power_on\n");
        bool power_state = true;
        if (!xen_cpu_pool_get_auto_power_on(session, &power_state, pool))
        {
            break;
        }
        if (power_state)
        {
            printf("Pool must not have attibute 'auto_power_on'\n");
            break;
        }

        // get_host_CPUs
        printf("cpu_pool.get_host_CPUs\n");
        if (!xen_cpu_pool_get_host_CPUs(session, &host_cpu_set, pool))
        {
            break;
        }
        if (host_cpu_set->size != 0)
        {
            printf("Pool must not have any attached cpus\n");
            break;
        }
        xen_host_cpu_set_free(host_cpu_set);
        host_cpu_set = NULL;


        // get_name_description
        printf("cpu_pool.get_name_description\n");
        if (!xen_cpu_pool_get_name_description(session, &name_description, pool))
        {
            break;
        }
        if (strcmp(NAME_DESCRIPTION, name_description) != 0)
        {
            printf("Pool has wrong name_description\n");
            break;
        }
        free(name_description);
        name_description = NULL;


        // get_name_label
        printf("cpu_pool.get_name_label\n");
        if (!xen_cpu_pool_get_name_label(session, &name_label, pool))
        {
            break;
        }
        if (strcmp(NAME_LABEL, name_label) != 0)
        {
            printf("Pool has wrong name_label\n");
            break;
        }
        free(name_label);
        name_label = NULL;

        // get_ncpu
        printf("cpu_pool.get_ncpu\n");
        if (!xen_cpu_pool_get_ncpu(session, &ncpu, pool))
        {
            break;
        }
        if (NCPU_VAL != ncpu)
        {
            printf("Pool has wrong ncpu\n");
            break;
        }

        // get_proposed_CPUs
        printf("cpu_pool.get_proposed_CPUs\n");
        if (!xen_cpu_pool_get_proposed_CPUs(session, &proposed_cpus, pool))
        {
            break;
        }
        if (proposed_cpus->size != 1)
        {
            printf("Pool has wrong proposed_cpus count\n");
            break;
        }
        xen_string_set_free(proposed_cpus);
        proposed_cpus = NULL;


        // get_other_config
        printf("cpu_pool.get_other_config\n");
        if (!xen_cpu_pool_get_other_config(session, &pool_other_config, pool))
        {
            break;
        }
        if (pool_other_config->size != 1)
        {
            printf("Pool has wrong other_config element count\n");
            break;
        }
        if ((strcmp(pool_other_config->contents[0].key, "type") != 0) ||
            (strcmp(pool_other_config->contents[0].val, "bs2000") != 0))
        {
            printf("Pool has wrong other_config attributes\n");
            break;
        }
        xen_string_string_map_free(pool_other_config);
        pool_other_config = NULL;


        // get_record
        printf("cpu_pool.get_record\n");
        if (!xen_cpu_pool_get_record(session, &cpu_pool_rec, pool))
        {
            break;
        }
        if ( (strcmp(cpu_pool_rec->name_label, NAME_LABEL) != 0) ||
             (strcmp(cpu_pool_rec->name_description, NAME_DESCRIPTION) != 0) ||
             (cpu_pool_rec->auto_power_on) ||
             (cpu_pool_rec->ncpu != NCPU_VAL) ||
             (cpu_pool_rec->started_vms->size != 0) ||
             (strcmp(cpu_pool_rec->sched_policy, SCHED_NAME) != 0) ||
             (cpu_pool_rec->proposed_cpus->size != 1) ||
             (cpu_pool_rec->host_cpus->size != 0) ||
             (cpu_pool_rec->activated) ||
             (strcmp(cpu_pool_rec->resident_on->u.handle, host) != 0) ||
             (strcmp(cpu_pool_rec->uuid, pool) != 0) ||
             (cpu_pool_rec->other_config->size != 1))
        {
            printf("Wrong record output\n");
            break;
        }
        xen_cpu_pool_record_free(cpu_pool_rec);
        cpu_pool_rec = NULL;


        // get_resident_on
        printf("cpu_pool.get_resident_on\n");
        if (!xen_cpu_pool_get_resident_on(session, &res_host, pool))
        {
            break;
        }
        if (strcmp(res_host, host) != 0)
        {
            printf("Wrong resident host returned\n");
            break;
        }
        xen_host_free(res_host);
        res_host = NULL;


        // get_sched_policy
        printf("cpu_pool.get_sched_policy\n");
        if (!xen_cpu_pool_get_sched_policy(session, &sched_policy, pool))
        {
            break;
        }
        if (strcmp(sched_policy, SCHED_NAME) != 0)
        {
            printf("Wrong sched_policy returned\n");
            break;
        }
        free(sched_policy);
        sched_policy = NULL;


        // get_started_VMs
        printf("cpu_pool.get_started_VMs\n");
        if (!xen_cpu_pool_get_started_VMs(session, &vm_set, pool))
        {
            break;
        }
        if (vm_set->size != 0)
        {
            printf("Wrong count of started VMs\n");
            break;
        }
        xen_vm_set_free(vm_set);
        vm_set = NULL;


        // get_uuid
        printf("cpu_pool.get_uuid\n");
        if (!xen_cpu_pool_get_uuid(session, &pool_uuid, pool))
        {
            break;
        }
        if (strcmp(pool_uuid, pool) != 0)
        {
            printf("Wrong Pool UUID returnd\n");
            break;
        }
        free(pool_uuid);
        pool_uuid = NULL;


        // set_auto_power_on
        printf("cpu_pool.set_auto_power_on\n");
        if (!xen_cpu_pool_set_auto_power_on(session, pool, true))
            break;


        // set_proposed_CPUs
        printf("cpu_pool.set_proposed_CPUs\n");
        proposed_CPUs_set = xen_string_set_alloc(2);
        proposed_CPUs_set->contents[0] = strdup("2");
        proposed_CPUs_set->contents[1] = strdup("4");
        if (!xen_cpu_pool_set_proposed_CPUs(session, pool, proposed_CPUs_set))
            break;
        xen_string_set_free(proposed_CPUs_set);
        proposed_CPUs_set = NULL;


        // add_to_proposed_CPUs
        printf("cpu_pool.add_to_proposed_CPUs\n");
        if (!xen_cpu_pool_add_to_proposed_CPUs(session, pool, "3"))
            break;


        // remove_from_proposed_CPUs
        printf("cpu_pool.remove_from_proposed_CPUs\n");
        if (!xen_cpu_pool_remove_from_proposed_CPUs(session, pool, "4"))
            break;


        // set_name_label
        printf("cpu_pool.set_name_label\n");
        if (!xen_cpu_pool_set_name_label(session, pool, NAME_LABEL_2))
            break;


        // set_name_description
        printf("cpu_pool.set_name_description\n");
        if (!xen_cpu_pool_set_name_description(session, pool, NAME_DESCRIPTION_2))
            break;


        // set_ncpu
        printf("cpu_pool.set_ncpu\n");
        if (!xen_cpu_pool_set_ncpu(session, pool, NCPU_VAL_2))
            break;


        // set_other_config
        printf("cpu_pool.set_other_config\n");
        pool_other_config = xen_string_string_map_alloc(2);
        pool_other_config->contents[0].key = strdup("test1");
        pool_other_config->contents[0].val = strdup("field1");
        pool_other_config->contents[1].key = strdup("test2");
        pool_other_config->contents[1].val = strdup("field2");
        if (!xen_cpu_pool_set_other_config(session, pool, pool_other_config))
            break;
        xen_string_string_map_free(pool_other_config);
        pool_other_config = NULL;


        // add_to_other_config
        printf("cpu_pool.add_to_other_config\n");
        if (!xen_cpu_pool_add_to_other_config(session, pool, "test3", "field3"))
            break;


        // remove_from_other_config
        printf("cpu_pool.remove_from_other_config\n");
        if (!xen_cpu_pool_remove_from_other_config(session, pool, "test2"))
            break;


        // set_sched_policy
        printf("cpu_pool.set_sched_policy\n");
        if (!xen_cpu_pool_set_sched_policy(session, pool, SCHED_NAME))
            break;


        // check get_record again
        printf("check cpu_pool record\n");
        if (!xen_cpu_pool_get_record(session, &cpu_pool_rec, pool))
        {
            break;
        }
        if ( (strcmp(cpu_pool_rec->name_label, NAME_LABEL_2) != 0) ||
             (strcmp(cpu_pool_rec->name_description, NAME_DESCRIPTION_2) != 0) ||
             (!cpu_pool_rec->auto_power_on) ||
             (cpu_pool_rec->ncpu != NCPU_VAL_2) ||
             (cpu_pool_rec->started_vms->size != 0) ||
             (strcmp(cpu_pool_rec->sched_policy, SCHED_NAME) != 0) ||
             (cpu_pool_rec->proposed_cpus->size != 2) ||
             (cpu_pool_rec->host_cpus->size != 0) ||
             (cpu_pool_rec->activated) ||
             (strcmp(cpu_pool_rec->resident_on->u.handle, host) != 0) ||
             (strcmp(cpu_pool_rec->uuid, pool) != 0) ||
             (cpu_pool_rec->other_config->size != 2))
        {
            printf("Wrong record output\n");
            break;
        }
        xen_cpu_pool_record_free(cpu_pool_rec);
        cpu_pool_rec = NULL;


        // activate pool
        printf("cpu_pool.activate\n");
        if (!xen_cpu_pool_activate(session, pool))
            break;


        // add_host_CPU_live
        printf("cpu_pool.add_host_CPU_live\n");
        if (!xen_host_cpu_get_unassigned_cpus(session, &host_cpu_set))
        {
            break;
        }
        if (host_cpu_set->size < 1)
        {
            printf("No free CPU found\n");
            break;
        }
        if (!xen_cpu_pool_add_host_CPU_live(session, pool, host_cpu_set->contents[0]))
            break;


        // remove_host_CPU_live
        printf("cpu_pool.remove_host_CPU_live\n");
        if (!xen_cpu_pool_remove_host_CPU_live(session, pool, host_cpu_set->contents[0]))
            break;

        xen_host_cpu_set_free(host_cpu_set);
        host_cpu_set = NULL;


        // check get_record again
        printf("check cpu_pool record\n");
        if (!xen_cpu_pool_get_record(session, &cpu_pool_rec, pool))
        {
            break;
        }
        if ( (strcmp(cpu_pool_rec->name_label, NAME_LABEL_2) != 0) ||
             (strcmp(cpu_pool_rec->name_description, NAME_DESCRIPTION_2) != 0) ||
             (!cpu_pool_rec->auto_power_on) ||
             (cpu_pool_rec->ncpu != NCPU_VAL_2) ||
             (cpu_pool_rec->started_vms->size != 0) ||
             (strcmp(cpu_pool_rec->sched_policy, SCHED_NAME) != 0) ||
             (cpu_pool_rec->proposed_cpus->size != 2) ||
             (cpu_pool_rec->host_cpus->size != 1) ||
             (!cpu_pool_rec->activated) ||
             (strcmp(cpu_pool_rec->resident_on->u.handle, host) != 0) ||
             (strcmp(cpu_pool_rec->uuid, pool) != 0) ||
             (cpu_pool_rec->other_config->size != 2))
        {
            printf("Wrong record output\n");
            break;
        }
        xen_cpu_pool_record_free(cpu_pool_rec);
        cpu_pool_rec = NULL;


        // deactivate pool
        printf("cpu_pool.deactivate\n");
        if (!xen_cpu_pool_deactivate(session, pool))
            break;


        // Pool delete
        if (!xen_cpu_pool_destroy(session, pool))
        {
            break;
        }
        xen_cpu_pool_free(pool);
        pool = NULL;

        // Tests OK
        printf("Pool Tests OK\n");
        rc= 0;
    }

    if (rc != 0)
    {
        print_error(session);
    }

    xen_cpu_pool_set_free(pools);
    xen_host_record_free(host_record);
    xen_cpu_pool_record_opt_free(cpu_pool_opt);
    xen_host_cpu_set_free(host_cpu_set);
    xen_host_cpu_record_free(host_cpu_record);
    xen_vm_set_free(vm_set);
    xen_cpu_pool_free(pool);
    xen_cpu_pool_free(pool_out);
    xen_string_string_map_free(pool_other_config);
    xen_vm_record_free(vm_record);
    xen_string_set_free(proposed_cpus);
    free(name_description);
    free(name_label);
    free(sched_policy);
    free(pool_uuid);
    xen_cpu_pool_record_free(cpu_pool_rec);
    xen_host_free(res_host);

    return rc;
}
#endif


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

    print_methods(session);
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

    xen_string_string_map *cpu_configuration;
    if (!xen_host_get_cpu_configuration(session, &cpu_configuration, host))
    {
        print_error(session);
        free(dmesg);
        xen_string_set_free(capabilities);
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

    char *sched_policy;
    if (!xen_host_get_sched_policy(session, &sched_policy, host))
    {
        print_error(session);
        xen_string_string_map_free(cpu_configuration);
        xen_string_set_free(capabilities);
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

    printf("In bytes, the VM UUID is ");
    for (int i = 0; i < 15; i++)
    {
        printf("%x, ", (unsigned int)vm_uuid_bytes[i]);
    }
    printf("%x.\n", (unsigned int)vm_uuid_bytes[15]);

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

    printf("Host has the following CPU configuration:\n");
    for (size_t i = 0; i < cpu_configuration->size; i++)
    {
        printf("  %s -> %s.\n", cpu_configuration->contents[i].key,
               cpu_configuration->contents[i].val);
    }

    printf("Current scheduler policy: %s.\n\n", sched_policy);

    printf("%s.\n", vm_record->uuid);

    printf("Resident on %s.\n", (char *)vm_record->resident_on->u.handle);

    printf("%s.\n", xen_vm_power_state_to_string(vm_record->power_state));

    xen_uuid_bytes_free(vm_uuid_bytes);
    xen_uuid_free(vm_uuid);

    xen_vm_record_free(vm_record);

#ifdef POOL_TESTS
    if (pool_tests(session, host) != 0)
        return 1;
#endif

    xen_host_free(host);
    xen_string_string_map_free(versions);
    free(dmesg);
    xen_string_set_free(supported_bootloaders);
    xen_string_set_free(capabilities);
    xen_string_string_map_free(cpu_configuration);
    free(sched_policy);

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
            .memory_static_max = 256 * 1024 * 1024,
            .memory_dynamic_max = 256 * 1024 * 1024,
            .memory_dynamic_min = 128 * 1024 * 1024,
            .memory_static_min = 128 * 1024 * 1024,
            .vcpus_params = vcpus_params,
            .vcpus_max = 4,
            .vcpus_at_startup = 2,
            .actions_after_shutdown = XEN_ON_NORMAL_EXIT_DESTROY,
            .actions_after_reboot = XEN_ON_NORMAL_EXIT_RESTART,
            .actions_after_crash = XEN_ON_CRASH_BEHAVIOUR_RESTART,
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
        printf("Created a new HVM VM, with UUID %s, VDI UUID %s, VBD "
               "UUID %s, and VNC console UUID %s.\n",
               vm_uuid, vdi0_uuid, vbd0_uuid, vnc_uuid);
    }
    else {
        printf("Created a new PV VM, with UUID %s, VDI UUID %s, and VBD "
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

    fflush(stdout);
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
        free(uuid);
        free(this_user);
        xen_session_record_free(record);
        print_error(session);
        return;
    }

    assert(!strcmp(record->uuid, uuid));
    assert(!strcmp(record->this_user, this_user));

    free(uuid);
    free(this_user);
    xen_session_record_free(record);

    fflush(stdout);
}


static int pstrcmp(const void *p1, const void *p2)
{
    return strcmp(*(char **)p1, *(char **)p2);
}


/**
 * Print the list of supported methods.
 */
static void print_methods(xen_session *session)
{
    xen_string_set *methods;

    if (!xen_host_list_methods(session, &methods))
    {
        print_error(session);
        goto done;
    }

    printf("%zd.\n", methods->size);
    qsort(methods->contents, methods->size, sizeof(char *), pstrcmp);

    printf("Supported methods:\n");
    for (size_t i = 0; i < methods->size; i++)
    {
        printf("  %s\n", methods->contents[i]);
    }
    fflush(stdout);

done:
    xen_string_set_free(methods);
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

    tm = localtime(&vm_metrics_record->start_time);
    my_strftime(time, 256, "VM running since %c, local time.\n", tm);
    printf(time);

    for (size_t i = 0; i < vm_metrics_record->vcpus_utilisation->size; i++)
    {
        printf("%"PRId64" -> %lf.\n",
               vm_metrics_record->vcpus_utilisation->contents[i].key,
               vm_metrics_record->vcpus_utilisation->contents[i].val);
    }

    printf("VCPU -> PCPU mapping:\n");
    for (size_t i = 0; i < vm_metrics_record->vcpus_cpu->size; i++)
    {
        printf("  %"PRId64" -> %"PRId64".\n",
               vm_metrics_record->vcpus_cpu->contents[i].key,
               vm_metrics_record->vcpus_cpu->contents[i].val);
    }

    printf("Live scheduling parameters:\n");
    for (size_t i = 0; i < vm_metrics_record->vcpus_params->size; i++)
    {
        printf("  %s -> %s.\n",
               vm_metrics_record->vcpus_params->contents[i].key,
               vm_metrics_record->vcpus_params->contents[i].val);
    }

    for (size_t i = 0; i < vm_metrics_record->vcpus_flags->size; i++)
    {
        printf("%"PRId64" -> ",
               vm_metrics_record->vcpus_flags->contents[i].key);
        xen_string_set *s = vm_metrics_record->vcpus_flags->contents[i].val;
        for (size_t j = 0; j < s->size; j++)
        {
            printf("%s", s->contents[j]);
            if (j + 1 != s->size)
            {
                printf(", ");
            }
        }
        printf("\n");
    }

    xen_vm_metrics_record_free(vm_metrics_record);
    xen_vm_metrics_free(vm_metrics);

    fflush(stdout);
}
