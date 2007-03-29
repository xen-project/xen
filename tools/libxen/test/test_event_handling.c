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

#include "xen_event.h"

//#define PRINT_XML

static void usage()
{
    fprintf(stderr,
"Usage:\n"
"\n"
"    test_event_handling <server> <username> <password>\n"
"\n"
"where\n"
"        <server>   is the server's host and port, e.g. localhost:9363;\n"
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


/**
 * Workaround for whinging GCCs, as suggested by strftime(3).
 */
static size_t my_strftime(char *s, size_t max, const char *fmt,
                          const struct tm *tm)
{
    return strftime(s, max, fmt, tm);
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

    struct xen_string_set *classes = xen_string_set_alloc(0);
    xen_event_register(session, classes);
    xen_string_set_free(classes);

    if (!session->ok)
    {
        print_error(session);
        CLEANUP;
        return 1;
    }

    while (true)
    {
        struct xen_event_record_set *events;
        if (!xen_event_next(session, &events))
        {
            print_error(session);
            CLEANUP;
            return 1;
        }

        for (size_t i = 0; i < events->size; i++)
        {
            xen_event_record *ev = events->contents[i];
            char time[256];
            struct tm *tm = localtime(&ev->timestamp);
            my_strftime(time, 256, "%c, local time", tm);
            printf("Event received: ID = %"PRId64", %s.\n", ev->id, time);
            switch (ev->operation)
            {
            case XEN_EVENT_OPERATION_ADD:
                printf("%s created with UUID %s.\n", ev->class, ev->obj_uuid);
                break;

            case XEN_EVENT_OPERATION_DEL:
                printf("%s with UUID %s deleted.\n", ev->class, ev->obj_uuid);
                break;

            case XEN_EVENT_OPERATION_MOD:
                printf("%s with UUID %s modified.\n", ev->class, ev->obj_uuid);
                break;
            default:
                assert(false);
            }
        }

        xen_event_record_set_free(events);
    }

    CLEANUP;

    return 0;
}
