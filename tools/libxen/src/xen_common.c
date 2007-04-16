/*
 *  Copyright (c) 2006-2007 XenSource, Inc.
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

#define _XOPEN_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include <libxml/xmlstring.h>
#include <libxml/xpath.h>

#include "xen_common.h"
#include "xen_host.h"
#include "xen_internal.h"
#include "xen_int_float_map.h"
#include "xen_int_int_map.h"
#include "xen_int_string_set_map.h"
#include "xen_string_string_map.h"


/*
 * Whether to ignore missing structure entries.  This is not something we
 * want to do, once the API has stabilised, as it indicates that the server is
 * broken, but at the moment, complaining is just slowing development down.
 */
#define PERMISSIVE 1


static xmlXPathCompExprPtr responsePath = NULL;
static xmlXPathCompExprPtr faultPath = NULL;


typedef struct
{
    size_t size;
    void *contents[];
} arbitrary_map;


typedef struct
{
    void *handle;
} arbitrary_record;


typedef struct
{
    bool is_record;
    union
    {
        char *handle;
        arbitrary_record *record;
    } u;
} arbitrary_record_opt;


static char *
make_body(const char *, abstract_value [], int);

static void
parse_result(xen_session *, const char *, const abstract_type *, void *);

static void
add_value(xmlNode *, const char *, const char *);
static void
add_param(xmlNode *, const char *, const char *);

static xmlNode *
add_param_struct(xmlNode *);
static xmlNode *
add_struct_array(xmlNode *, const char *);
static xmlNode *
add_nested_struct(xmlNode *, const char *);
static void
add_struct_member(xmlNode *, const char *, const char *, const char *);
static void
add_unnamed_value(xmlNode *, const char *, const char *, const char *);

static void
add_struct_value(const struct abstract_type *, void *,
                 void (*)(xmlNode *, const char *, const char *,
                          const char *),
                 const char *, xmlNode *);

static xmlNode *
add_container(xmlNode *parent, const char *name);

static void
call_raw(xen_session *, const char *, abstract_value [], int,
         const abstract_type *, void *);

static void
parse_structmap_value(xen_session *, xmlNode *, const abstract_type *,
                      void *);

static size_t size_of_member(const abstract_type *);

static const char *
get_val_as_string(const struct abstract_type *, void *, char *, size_t);


void
xen_init(void)
{
    responsePath =
        xmlXPathCompile(
            BAD_CAST(
                "/methodResponse/params/param/value/struct/member/value"));
    faultPath =
        xmlXPathCompile(
            BAD_CAST("/methodResponse/fault/value/struct/member/value"));
}


void
xen_fini(void)
{
    xmlXPathFreeCompExpr(responsePath);
    xmlXPathFreeCompExpr(faultPath);
    responsePath = NULL;
    faultPath = NULL;
}


void
xen_session_record_free(xen_session_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->uuid);
    xen_host_record_opt_free(record->this_host);
    free(record->this_user);
    free(record);
}


xen_session *
xen_session_login_with_password(xen_call_func call_func, void *handle,
                                const char *uname, const char *pwd)
{
    abstract_value params[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uname },
            { .type = &abstract_type_string,
              .u.string_val = pwd }
        };

    xen_session *session = malloc(sizeof(xen_session));
    session->call_func = call_func;
    session->handle = handle;
    session->session_id = NULL;
    session->ok = true;
    session->error_description = NULL;
    session->error_description_count = 0;

    call_raw(session, "session.login_with_password", params, 2,
             &abstract_type_string, &session->session_id);

    return session;
}


void
xen_session_logout(xen_session *session)
{
    abstract_value params[] =
        {
        };
    xen_call_(session, "session.logout", params, 0, NULL, NULL);

    if (session->error_description != NULL)
    {
        for (int i = 0; i < session->error_description_count; i++)
        {
            free(session->error_description[i]);
        }
        free(session->error_description);
    }

    free((char *)session->session_id);
    free(session);
}


void
xen_session_clear_error(xen_session *session)
{
    if (session->error_description != NULL)
    {
        for (int i = 0; i < session->error_description_count; i++)
        {
            free(session->error_description[i]);
        }
        free(session->error_description);
    }
    session->error_description = NULL;
    session->error_description_count = 0;
    session->ok = true;
}


bool
xen_session_get_uuid(xen_session *session, char **result,
                     xen_session *self_session)
{
    abstract_value params[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self_session->session_id }
        };

    xen_call_(session, "session.get_uuid", params, 1,
              &abstract_type_string, result);
    return session->ok;
}


bool
xen_session_get_this_host(xen_session *session, xen_host *result,
                          xen_session *self_session)
{
    abstract_value params[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self_session->session_id }
        };

    xen_call_(session, "session.get_this_host", params, 1,
              &abstract_type_string, result);
    return session->ok;
}


bool
xen_session_get_this_user(xen_session *session, char **result,
                          xen_session *self_session)
{
    abstract_value params[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self_session->session_id }
        };

    xen_call_(session, "session.get_this_user", params, 1,
              &abstract_type_string, result);
    return session->ok;
}


bool
xen_session_get_last_active(xen_session *session, time_t *result,
                            xen_session *self_session)
{
    abstract_value params[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self_session->session_id }
        };

    xen_call_(session, "session.get_last_active", params, 1,
              &abstract_type_datetime, result);
    return session->ok;
}


static const struct_member xen_session_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_session_record, uuid) },
        { .key = "this_host",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_session_record, this_host) },
        { .key = "this_user",
          .type = &abstract_type_string,
          .offset = offsetof(xen_session_record, this_user) },
        { .key = "last_active",
          .type = &abstract_type_datetime,
          .offset = offsetof(xen_session_record, last_active) },
    };

const abstract_type xen_session_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_session_record),
       .member_count =
           sizeof(xen_session_record_struct_members) / sizeof(struct_member),
       .members = xen_session_record_struct_members
    };


bool
xen_session_get_record(xen_session *session, xen_session_record **result,
                       xen_session *self_session)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self_session->session_id }
        };

    abstract_type result_type = xen_session_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("session.get_record");

    return session->ok;
}


#define X "%02x"
#define UUID_FORMAT X X X X "-" X X "-" X X "-" X X "-" X X X X X X


bool
xen_uuid_string_to_bytes(char *uuid, char **bytes)
{
    unsigned int buf[16];

    *bytes = NULL;
    
    if (strlen(uuid) != 36)
        return false;

    if (16 != sscanf(uuid, UUID_FORMAT,
                     buf + 0, buf + 1, buf + 2, buf + 3,
                     buf + 4, buf + 5,
                     buf + 6, buf + 7,
                     buf + 8, buf + 9,
                     buf + 10, buf + 11, buf + 12, buf + 13, buf + 14,
                       buf + 15))
    {
        return false;
    }

    *bytes = malloc(16);
    if (*bytes == NULL)
        return false;

    for (int i = 0; i < 16; i++) {
        (*bytes)[i] = (char)buf[i];
    }

    return true;
}


bool
xen_uuid_bytes_to_string(char *bytes, char **uuid)
{
    *uuid = malloc(37);
    if (*uuid == NULL)
        return false;

    sprintf(*uuid, UUID_FORMAT,
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);

    return true;
}


#undef UUID_FORMAT
#undef X


void
xen_uuid_free(char *uuid)
{
    free(uuid);
}


void
xen_uuid_bytes_free(char *bytes)
{
    free(bytes);
}


/**
 * @param value A pointer to the correct location as per the given
 * result_type.  Will be populated if the call succeeds.  In that case, and if
 * value is a char **, the char * itself must be freed by the caller.
 */
void
xen_call_(xen_session *s, const char *method_name,
          abstract_value params[], int param_count,
          const abstract_type *result_type, void *value)
{
    if (!s->ok)
    {
        return;
    }

    abstract_value *full_params =
        malloc(sizeof(abstract_value) * (param_count + 1));

    full_params[0].type = &abstract_type_string;
    full_params[0].u.string_val = s->session_id;

    memcpy(full_params + 1, params, param_count * sizeof(abstract_value));

    call_raw(s, method_name, full_params, param_count + 1, result_type,
             value);

    free(full_params);
}


static bool
bufferAdd(const void *data, size_t len, void *buffer)
{
    return 0 == xmlBufferAdd((xmlBufferPtr)buffer, data, len);
}


static void
call_raw(xen_session *s, const char *method_name,
         abstract_value params[], int param_count,
         const abstract_type *result_type, void *value)
{
    xmlBufferPtr buffer = xmlBufferCreate();
    char *body = make_body(method_name, params, param_count);
    int error_code =
        s->call_func(body, strlen(body), s->handle, buffer, &bufferAdd);
    free(body);
    if (error_code)
    {
        char **strings = malloc(2 * sizeof(char *));

        strings[0] = xen_strdup_("TRANSPORT_FAULT");
        strings[1] = malloc(20);
        snprintf(strings[1], 20, "%d", error_code);

        s->ok = false;
        s->error_description = strings;
        s->error_description_count = 2;
    }
    else
    {
        parse_result(s, (char *)xmlBufferContent(buffer), result_type, value);
    }
    xmlBufferFree(buffer);
}


static void server_error(xen_session *session, const char *error_string)
{
    if (!session->ok)
    {
        /* Don't wipe out the earlier error message with this one. */
        return;
    }

    char **strings = malloc(2 * sizeof(char *));

    strings[0] = xen_strdup_("SERVER_FAULT");
    strings[1] = xen_strdup_(error_string);

    session->ok = false;
    session->error_description = strings;
    session->error_description_count = 2;
}


static void server_error_2(xen_session *session, const char *error_string,
                           const char *param)
{
    if (!session->ok)
    {
        /* Don't wipe out the earlier error message with this one. */
        return;
    }

    char **strings = malloc(3 * sizeof(char *));

    strings[0] = xen_strdup_("SERVER_FAULT_2");
    strings[1] = xen_strdup_(error_string);
    strings[2] = xen_strdup_(param);

    session->ok = false;
    session->error_description = strings;
    session->error_description_count = 3;
}


static bool is_node(xmlNode *n, char *type)
{
    return
        n->type == XML_ELEMENT_NODE &&
        0 == strcmp((char *)n->name, type);
}


static bool is_container_node(xmlNode *n, char *type)
{
    return
        is_node(n, type) &&
        n->children != NULL &&
        n->children == n->last &&
        n->children->type == XML_ELEMENT_NODE;
}


/**
 * @return The contents of the given value, or NULL if this is not a node with
 * the given type.  If not NULL, the result must be freed with xmlFree().
 */
static xmlChar *string_from_value(xmlNode *n, char *type)
{
    /*
      <value><type>XYZ</type></value> is normal, but the XML-RPC spec also
      allows <value>XYZ</value> where XYZ is to be interpreted as a string.
    */

    if (is_container_node(n, "value") &&
        0 == strcmp((char *)n->children->name, type))
    {
        return
            n->children->children == NULL ?
                xmlStrdup(BAD_CAST("")) :
                xmlNodeGetContent(n->children->children);
    }
    else if (0 == strcmp(type, "string") && is_node(n, "value"))
    {
        return
            n->children == NULL ?
                xmlStrdup(BAD_CAST("")) :
                xmlNodeGetContent(n->children);
    }
    else
    {
        return NULL;
    }
}


/**
 * Find the name node that is a child of the given one, and return its
 * contents, or NULL if this has no such node.  If not NULL, the result must
 * be freed with xmlFree().
 */
static xmlChar *string_from_name(xmlNode *n)
{
    xmlNode *cur = n->children;

    while (cur != NULL)
    {
        if (0 == strcmp((char *)cur->name, "name"))
        {
            return xmlNodeGetContent(cur);
        }
        cur = cur->next;
    }

    return NULL;
}


static int count_children(xmlNode *n, const char *name)
{
    int result = 0;
    xmlNode *cur = n->children;

    while (cur != NULL)
    {
        if (0 == strcmp((char *)cur->name, name))
        {
            result++;
        }
        cur = cur->next;
    }

    return result;
}


static void destring(xen_session *s, xmlChar *name, const abstract_type *type,
                     void *value)
{
    switch (type->typename)
    {
    case STRING:
        *((char **)value) = xen_strdup_((const char *)name);
        break;

    case INT:
        *((int64_t *)value) = atoll((const char *)name);
        break;

    case FLOAT:
        *((double *)value) = atof((const char *)name);
        break;

    default:
        server_error(s, "Invalid Map key type");
    }
}


/**
 * result_type : STRING   => value : char **, the char * is yours.
 * result_type : ENUM     => value : int *
 * result_type : INT      => value : int64_t *
 * result_type : FLOAT    => value : double *
 * result_type : BOOL     => value : bool *
 * result_type : DATETIME => value : time_t *
 * result_type : SET      => value : arbitrary_set **, the set is yours.
 * result_type : MAP      => value : arbitrary_map **, the map is yours.
 * result_type : OPT      => value : arbitrary_record_opt **,
 *                                   the record is yours, the handle is
 *                                   filled.
 * result_type : STRUCT   => value : void **, the void * is yours.
 */
static void parse_into(xen_session *s, xmlNode *value_node,
                       const abstract_type *result_type, void *value,
                       int slot)
{
    if (result_type == NULL)
    {
        xmlChar *string = string_from_value(value_node, "string");
        if (string == NULL || strcmp((char *)string, ""))
        {
            server_error(s,
                         "Expected Void from the server, but didn't get it");
        }
        else
        {
            free(string);
        }

        return;
    }

    switch (result_type->typename)
    {
    case STRING:
    {
        xmlChar *string = string_from_value(value_node, "string");
        if (string == NULL)
        {
            server_error(
                s, "Expected a String from the server, but didn't get one");
        }
        else
        {
            ((char **)value)[slot] = xen_strdup_((const char *)string);
            free(string);
        }
    }
    break;

    case ENUM:
    {
        xmlChar *string = string_from_value(value_node, "string");
        if (string == NULL)
        {
#if PERMISSIVE
            fprintf(stderr,
                    "Expected an Enum from the server, but didn't get one\n");
            ((int *)value)[slot] = 0;
#else
            server_error(
                s, "Expected an Enum from the server, but didn't get one");
#endif
        }
        else
        {
            ((int *)value)[slot] =
                result_type->enum_demarshaller(s, (const char *)string);
            free(string);
        }
    }
    break;

    case INT:
    {
        xmlChar *string = string_from_value(value_node, "string");
        if (string == NULL)
        {
            server_error(
                s, "Expected an Int from the server, but didn't get one");
        }
        else
        {
            ((int64_t *)value)[slot] = (int64_t)atoll((char *)string);
            free(string);
        }
    }
    break;

    case FLOAT:
    {
        xmlChar *string = string_from_value(value_node, "double");
        if (string == NULL)
        {
#if PERMISSIVE
            fprintf(stderr,
                    "Expected a Float from the server, but didn't get one\n");
            ((double *)value)[slot] = 0.0;
#else
            server_error(
                s, "Expected a Float from the server, but didn't get one");
#endif
        }
        else
        {
            ((double *)value)[slot] = atof((char *)string);
            free(string);
        }
    }
    break;

    case BOOL:
    {
        xmlChar *string = string_from_value(value_node, "boolean");
        if (string == NULL)
        {
#if PERMISSIVE
            fprintf(stderr,
                    "Expected a Bool from the server, but didn't get one\n");
            ((bool *)value)[slot] = false;
#else
            server_error(
                s, "Expected a Bool from the server, but didn't get one");
#endif
        }
        else
        {
            ((bool *)value)[slot] = (0 == strcmp((char *)string, "1"));
            free(string);
        }
    }
    break;

    case DATETIME:
    {
        xmlChar *string = string_from_value(value_node, "dateTime.iso8601");
        if (string == NULL)
        {
            server_error(
                s, "Expected an DateTime from the server but didn't get one");
        }
        else
        {
            struct tm tm;
            memset(&tm, 0, sizeof(tm));
            strptime((char *)string, "%Y%m%dT%H:%M:%S", &tm);
            ((time_t *)value)[slot] = (time_t)mktime(&tm);
            free(string);
        }
    }
    break;

    case SET:
    {
        if (!is_container_node(value_node, "value") ||
            !is_container_node(value_node->children, "array"))
        {
            server_error(s,
                         "Expected Set from the server, but didn't get it");
        }
        else
        {
            xmlNode *data_node = value_node->children->children;
            int n = count_children(data_node, "value");

            const abstract_type *member_type = result_type->child;
            size_t member_size = size_of_member(member_type);

            arbitrary_set *set =
                calloc(1, sizeof(arbitrary_set) + member_size * n);
            set->size = n;
            int i = 0;
            xmlNode *cur = data_node->children;

            while (cur != NULL)
            {
                if (0 == strcmp((char *)cur->name, "value"))
                {
                    parse_into(s, cur, member_type, set->contents, i);
                    i++;
                }
                cur = cur->next;
            }

            ((arbitrary_set **)value)[slot] = set;
        }
    }
    break;

    case MAP:
    {
        if (!is_container_node(value_node, "value") ||
            value_node->children->type != XML_ELEMENT_NODE ||
            0 != strcmp((char *)value_node->children->name, "struct"))
        {
            server_error(s,
                         "Expected Map from the server, but didn't get it");
        }
        else
        {
            xmlNode *struct_node = value_node->children;
            int n = count_children(struct_node, "member");

            size_t struct_size = result_type->struct_size;

            const struct struct_member *key_member = result_type->members;
            const struct struct_member *val_member = result_type->members + 1;

            arbitrary_map *map =
                calloc(1, sizeof(arbitrary_map) + struct_size * n);
            map->size = n;
            int i = 0;
            xmlNode *cur = struct_node->children;

            while (cur != NULL)
            {
                if (0 == strcmp((char *)cur->name, "member"))
                {
                    if (cur->children == NULL || cur->last == cur->children)
                    {
                        server_error(s, "Malformed Map");
                        free(map);
                        return;
                    }

                    xmlChar *name = string_from_name(cur);
                    if (name == NULL)
                    {
                        server_error(s, "Malformed Map");
                        free(map);
                        return;
                    }

                    destring(s, name, key_member->type,
                             ((void *)(map + 1)) +
                             (i * struct_size) +
                             key_member->offset);
                    xmlFree(name);
                    if (!s->ok)
                    {
                        free(map);
                        return;
                    }

                    parse_structmap_value(s, cur, val_member->type,
                                          ((void *)(map + 1)) +
                                          (i * struct_size) +
                                          val_member->offset);
                    if (!s->ok)
                    {
                        free(map);
                        return;
                    }
                    i++;
                }
                cur = cur->next;
            }

            ((arbitrary_map **)value)[slot] = map;
        }
    }
    break;

    case STRUCT:
    {
        if (!is_container_node(value_node, "value") ||
            value_node->children->type != XML_ELEMENT_NODE ||
            0 != strcmp((char *)value_node->children->name, "struct") ||
            value_node->children->children == NULL)
        {
            server_error(s,
                         "Expected Map from the server, but didn't get it");
        }
        else
        {
            xmlNode *struct_node = value_node->children;

            void *result = calloc(1, result_type->struct_size);
            xmlNode *cur = struct_node->children;

            size_t member_count = result_type->member_count;

            const struct_member **checklist =
                malloc(sizeof(const struct_member *) * member_count);
            int seen_count = 0;

            while (cur != NULL)
            {
                if (0 == strcmp((char *)cur->name, "member"))
                {
                    if (cur->children == NULL || cur->last == cur->children)
                    {
                        server_error(s, "Malformed Struct");
                        free(result);
                        free(checklist);
                        return;
                    }

                    xmlChar *name = string_from_name(cur);
                    if (name == NULL)
                    {
                        server_error(s, "Malformed Struct");
                        free(result);
                        free(checklist);
                        return;
                    }

                    for (size_t i = 0; i < member_count; i++)
                    {
                        const struct_member *mem = result_type->members + i;

                        if (0 == strcmp((char *)name, mem->key))
                        {
                            parse_structmap_value(s, cur, mem->type,
                                                  result + mem->offset);
                            checklist[seen_count] = mem;
                            seen_count++;
                            break;
                        }
                    }

                    /* Note that we're skipping unknown fields implicitly.
                       This means that we'll be forward compatible with
                       new servers. */

                    xmlFree(name);

                    if (!s->ok)
                    {
                        free(result);
                        free(checklist);
                        return;
                    }
                }
                cur = cur->next;
            }

            /* Check that we've filled all fields. */
            for (size_t i = 0; i < member_count; i++)
            {
                const struct_member *mem = result_type->members + i;
                int j;

                for (j = 0; j < seen_count; j++)
                {
                    if (checklist[j] == mem)
                    {
                        break;
                    }
                }

                if (j == seen_count)
                {
#if PERMISSIVE
                    fprintf(stderr,
                            "Struct did not contain expected field %s.\n",
                            mem->key);
#else
                    server_error_2(s,
                                   "Struct did not contain expected field",
                                   mem->key);
                    free(result);
                    free(checklist);
                    return;
#endif
                }
            }

            free(checklist);
            ((void **)value)[slot] = result;
        }
    }
    break;

    case REF:
    {
        arbitrary_record_opt *record_opt =
            calloc(1, sizeof(arbitrary_record_opt));

        record_opt->is_record = false;
        parse_into(s, value_node, &abstract_type_string,
                   &(record_opt->u.handle), 0);

        ((arbitrary_record_opt **)value)[slot] = record_opt;
    }
    break;

    default:
        assert(false);
    }
}


static size_t size_of_member(const abstract_type *type)
{
    switch (type->typename)
    {
    case STRING:
        return sizeof(char *);

/*
    case INT:
        return sizeof(int64_t);

    case FLOAT:
        return sizeof(double);

    case BOOL:
        return sizeof(bool);
*/
    case ENUM:
        return sizeof(int);

    case REF:
        return sizeof(arbitrary_record_opt *);

    case STRUCT:
        return type->struct_size;

    default:
        assert(false);
    }
}


static void parse_structmap_value(xen_session *s, xmlNode *n,
                                  const abstract_type *type, void *value)
{
    xmlNode *cur = n->children;

    while (cur != NULL)
    {
        if (0 == strcmp((char *)cur->name, "value"))
        {
            parse_into(s, cur, type, value, 0);
            return;
        }
        cur = cur->next;
    }

    server_error(s, "Missing value in Map/Struct");
}


static void parse_fault(xen_session *session, xmlXPathContextPtr xpathCtx)
{
    xmlXPathObjectPtr xpathObj = xmlXPathCompiledEval(faultPath, xpathCtx);
    if (xpathObj == NULL)
    {
        server_error(session, "Method response is neither result nor fault");
        return;
    }

    if (xpathObj->type != XPATH_NODESET ||
        xpathObj->nodesetval->nodeNr != 2)
    {
        xmlXPathFreeObject(xpathObj);
        server_error(session, "Method response is neither result nor fault");
        return;
    }

    xmlNode *fault_node0 = xpathObj->nodesetval->nodeTab[0];
    xmlNode *fault_node1 = xpathObj->nodesetval->nodeTab[1];

    xmlChar *fault_code_str = string_from_value(fault_node0, "int");
    if (fault_code_str == NULL)
    {
        fault_code_str = string_from_value(fault_node0, "i4");
    }
    if (fault_code_str == NULL)
    {
        xmlXPathFreeObject(xpathObj);
        server_error(session, "Fault code is malformed");
        return;
    }

    xmlChar *fault_string_str = string_from_value(fault_node1, "string");
    if (fault_string_str == NULL)
    {
        xmlFree(fault_code_str);
        xmlXPathFreeObject(xpathObj);
        server_error(session, "Fault string is malformed");
        return;
    }

    char **strings = malloc(3 * sizeof(char *));

    strings[0] = xen_strdup_("FAULT");
    strings[1] = xen_strdup_((char *)fault_code_str);
    strings[2] = xen_strdup_((char *)fault_string_str);

    session->ok = false;
    session->error_description = strings;
    session->error_description_count = 3;

    xmlFree(fault_code_str);
    xmlFree(fault_string_str);
    xmlXPathFreeObject(xpathObj);
}


static void parse_failure(xen_session *session, xmlNode *node)
{
    abstract_type error_description_type =
        { .typename = SET,
          .child = &abstract_type_string };
    arbitrary_set *error_descriptions;

    parse_into(session, node, &error_description_type, &error_descriptions,
               0);

    if (session->ok)
    {
        session->ok = false;

        char **c = (char **)error_descriptions->contents;
        int n = error_descriptions->size;

        char **strings = malloc(n * sizeof(char *));
        for (int i = 0; i < n; i++)
        {
            strings[i] = c[i];
        }

        session->error_description_count = n;
        session->error_description = strings;
    }

    free(error_descriptions);
}


/**
 * Parameters as for xen_call_() above.
 */
static void parse_result(xen_session *session, const char *result,
                         const abstract_type *result_type, void *value)
{
    xmlDocPtr doc =
        xmlReadMemory(result, strlen(result), "", NULL, XML_PARSE_NONET);

    if (doc == NULL)
    {
        server_error(session, "Couldn't parse the server response");
        return;
    }

    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL)
    {
        xmlFreeDoc(doc);
        server_error(session, "Couldn't create XPath context");
        return;
    }

    xmlXPathObjectPtr xpathObj =
        xmlXPathCompiledEval(responsePath, xpathCtx);
    if (xpathObj == NULL)
    {
        parse_fault(session, xpathCtx);

        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc);
        return;
    }

    if  (xpathObj->type != XPATH_NODESET ||
         xpathObj->nodesetval->nodeNr != 2)
    {
        parse_fault(session, xpathCtx);

        xmlXPathFreeObject(xpathObj);
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc);
        return;
    }

    xmlNode *node0 = xpathObj->nodesetval->nodeTab[0];
    xmlNode *node1 = xpathObj->nodesetval->nodeTab[1];

    xmlChar *status_code = string_from_value(node0, "string");
    if (status_code == NULL)
    {
        xmlXPathFreeObject(xpathObj);
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc);
        server_error(session, "Server response does not have a Status");
        return;
    }

    if (strcmp((char *)status_code, "Success"))
    {
        parse_failure(session, node1);

        xmlFree(status_code);
        xmlXPathFreeObject(xpathObj);
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return;
    }

    parse_into(session, node1, result_type, value, 0);

    xmlFree(status_code);
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
}


static void
make_body_add_type(enum abstract_typename typename, abstract_value *v,
                   xmlNode *params_node)
{
    char buf[20];
    switch (typename)
    {
    case STRING:
        add_param(params_node, "string", v->u.string_val);
        break;

    case INT:
        snprintf(buf, sizeof(buf), "%"PRId64, v->u.int_val);
        add_param(params_node, "string", buf);
        break;

    case FLOAT:
        snprintf(buf, sizeof(buf), "%lf", v->u.float_val);
        add_param(params_node, "double", buf);
        break;

    case BOOL:
        add_param(params_node, "boolean", v->u.bool_val ? "1" : "0");
        break;
        
    case VOID:
        add_param(params_node, "string", "");
        break;

    case ENUM:
        add_param(params_node, "string",
                  v->type->enum_marshaller(v->u.enum_val));
        break;

    case SET:
    {
        const struct abstract_type *member_type = v->type->child;
        arbitrary_set *set_val = v->u.struct_val;
        abstract_value v;
        xmlNode *data_node = add_param_struct(params_node);

        for (size_t i = 0; i < set_val->size; i++)
        {
            switch (member_type->typename) {
                case STRING:
                    v.u.string_val = (char *)set_val->contents[i];
                    make_body_add_type(member_type->typename, &v, data_node);
                    break;
                default:
                    assert(false);
            }
        }
    }
    break;

    case STRUCT:
    {
        size_t member_count = v->type->member_count;

        xmlNode *struct_node = add_param_struct(params_node);

        for (size_t i = 0; i < member_count; i++)
        {
            const struct struct_member *mem = v->type->members + i;
            const char *key = mem->key;
            void *struct_value = v->u.struct_val;

            add_struct_value(mem->type, struct_value + mem->offset,
                             add_struct_member, key, struct_node);
        }
    }
    break;

    case MAP:
    {
        const struct struct_member *member = v->type->members;
        arbitrary_map *map_val = v->u.struct_val;
        xmlNode *param_node = add_param_struct(params_node);
        for (size_t i = 0; i < map_val->size; i++) {
            enum abstract_typename typename_key = member[0].type->typename;
            enum abstract_typename typename_val = member[1].type->typename;
            int offset_key = member[0].offset;
            int offset_val = member[1].offset;
            int struct_size = v->type->struct_size;

            switch (typename_key) {
            case STRING: {
                char **addr = (void *)(map_val + 1) +
                             (i * struct_size) +
                             offset_key;
                char *key = *addr;

                switch (typename_val) {
                case STRING: {
                    char *val;
                    addr = (void *)(map_val + 1) +
                           (i * struct_size) +
                           offset_val;
                    val = *addr;
                    add_struct_member(param_node, key, "string", val);
                    break;
                }
                default:
                    assert(false);
                }
                break;
            }
            default:
                assert(false);
            }
        }
    }
    break;


    default:
        assert(false);
    }
}


static char *
make_body(const char *method_name, abstract_value params[], int param_count)
{
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    xmlNode *methodCall = xmlNewNode(NULL, BAD_CAST "methodCall");
    xmlDocSetRootElement(doc, methodCall);

    xmlNewChild(methodCall, NULL, BAD_CAST "methodName",
                BAD_CAST method_name);

    xmlNode *params_node =
        xmlNewChild(methodCall, NULL, BAD_CAST "params", NULL);

    for (int p = 0; p < param_count; p++)
    {
        abstract_value *v = params + p;
        make_body_add_type(v->type->typename, v, params_node);
    }

    xmlBufferPtr buffer = xmlBufferCreate();
    xmlSaveCtxtPtr save_ctxt =
        xmlSaveToBuffer(buffer, NULL, XML_SAVE_NO_XHTML);

    if (xmlSaveDoc(save_ctxt, doc) == -1)
    {
        return NULL;
    }

    xmlFreeDoc(doc);
    xmlSaveClose(save_ctxt);
    xmlChar *content = xmlStrdup(xmlBufferContent(buffer));
    xmlBufferFree(buffer);
    return (char *)content;
}


static void
add_struct_value(const struct abstract_type *type, void *value,
                 void (*adder)(xmlNode *node, const char *key,
                               const char *type, const char *val),
                 const char *key, xmlNode *node)
{
    char buf[20];

    switch (type->typename)
    {
    case REF:
    case STRING:
    case INT:
    case ENUM:
    {
        const char *val_as_string =
            get_val_as_string(type, value, buf, sizeof(buf));
        adder(node, key, "string", val_as_string);
    }
    break;

    case FLOAT:
    {
        double val = *(double *)value;
        snprintf(buf, sizeof(buf), "%lf", val);
        adder(node, key, "double", buf);
    }
    break;

    case BOOL:
    {
        bool val = *(bool *)value;
        adder(node, key, "boolean", val ? "1" : "0");
    }
    break;

    case SET:
    {
        const struct abstract_type *member_type = type->child;
        size_t member_size = size_of_member(member_type);
        arbitrary_set *set_val = *(arbitrary_set **)value;

        if (set_val != NULL)
        {
            xmlNode *data_node = add_struct_array(node, key);

            for (size_t i = 0; i < set_val->size; i++)
            {
                void *member_value = (char *)set_val->contents +
                                     (i * member_size);
                add_struct_value(member_type, member_value,
                                 add_unnamed_value, NULL, data_node);
            }
        }
    }
    break;

    case STRUCT:
    {
        assert(false);
        /* XXX Nested structures aren't supported yet, but
           fortunately we don't need them, because we don't have
           any "deep create" calls.  This will need to be
           fixed. */
    }
    break;

    case MAP:
    {
        size_t member_size = type->struct_size;
        const struct abstract_type *l_type = type->members[0].type;
        const struct abstract_type *r_type = type->members[1].type;
        int l_offset = type->members[0].offset;
        int r_offset = type->members[1].offset;

        arbitrary_map *map_val = *(arbitrary_map **)value;

        if (map_val != NULL)
        {
            xmlNode *struct_node = add_nested_struct(node, key);

            for (size_t i = 0; i < map_val->size; i++)
            {
                void *contents = (void *)map_val->contents;
                void *l_value = contents + (i * member_size) + l_offset;
                void *r_value = contents + (i * member_size) + r_offset;

                const char *l_value_as_string =
                    get_val_as_string(l_type, l_value, buf, sizeof(buf));

                add_struct_value(r_type, r_value, add_struct_member,
                                 l_value_as_string, struct_node);
            }
        }
    }
    break;

    default:
        assert(false);
    }
}


static const char *
get_val_as_string(const struct abstract_type *type, void *value, char *buf,
                  size_t bufsize)
{
    switch (type->typename)
    {
    case REF:
    {
        arbitrary_record_opt *val = *(arbitrary_record_opt **)value;
        if (val != NULL)
        {
            if (val->is_record)
            {
                return val->u.record->handle;
            }
            else
            {
                return val->u.handle;
            }
        }
        else
        {
            return NULL;
        }
    }
    break;

    case STRING:
    {
        return *(char **)value;
    }
    break;

    case INT:
    {
        int64_t val = *(int64_t *)value;
        snprintf(buf, bufsize, "%"PRId64, val);
        return buf;
    }
    break;

    case ENUM:
    {
        int val = *(int *)value;
        return type->enum_marshaller(val);
    }
    break;

    default:
        assert(false);
    }
}


static xmlNode *
add_container(xmlNode *parent, const char *name)
{
    return xmlNewChild(parent, NULL, BAD_CAST name, NULL);
}


static void
add_param(xmlNode *params_node, const char *type, const char *value)
{
    xmlNode *param_node = add_container(params_node, "param");
    add_value(param_node, type, value);
}


static void
add_value(xmlNode *parent, const char *type, const char *value)
{
    xmlNode *value_node = add_container(parent, "value");
    xmlNewChild(value_node, NULL, BAD_CAST type, BAD_CAST value);
}


static void
add_unnamed_value(xmlNode *parent, const char *name, const char *type,
                  const char *value)
{
    (void)name;
    add_value(parent, type, value);
}


static xmlNode *
add_param_struct(xmlNode *params_node)
{
    xmlNode *param_node = add_container(params_node, "param");
    xmlNode *value_node = add_container(param_node,  "value");

    return xmlNewChild(value_node, NULL, BAD_CAST "struct", NULL);
}


static void
add_struct_member(xmlNode *struct_node, const char *name, const char *type,
                  const char *value)
{
    xmlNode *member_node = add_container(struct_node, "member");

    xmlNewChild(member_node, NULL, BAD_CAST "name", BAD_CAST name);

    add_value(member_node, type, value);
}


static xmlNode *
add_struct_array(xmlNode *struct_node, const char *name)
{
    xmlNode *member_node = add_container(struct_node, "member");

    xmlNewChild(member_node, NULL, BAD_CAST "name", BAD_CAST name);

    xmlNode *value_node = add_container(member_node, "value");
    xmlNode *array_node = add_container(value_node,  "array");

    return add_container(array_node,  "data");
}


static xmlNode *
add_nested_struct(xmlNode *struct_node, const char *name)
{
    xmlNode *member_node = add_container(struct_node, "member");

    xmlNewChild(member_node, NULL, BAD_CAST "name", BAD_CAST name);

    xmlNode *value_node = add_container(member_node, "value");

    return add_container(value_node, "struct");
}


int xen_enum_lookup_(xen_session *session, const char *str,
                     const char **lookup_table, int n)
{
    if (str != NULL)
    {
        for (int i = 0; i < n; i++)
        {
            if (0 == strcmp(str, lookup_table[i]))
            {
                return i;
            }
        }
    }

    server_error_2(session, "Bad enum string", str);
    return 0;
}


char *
xen_strdup_(const char *in)
{
    char *result = malloc(strlen(in) + 1);
    strcpy(result, in);
    return result;
}


const abstract_type abstract_type_string = { .typename = STRING };
const abstract_type abstract_type_int = { .typename = INT };
const abstract_type abstract_type_float = { .typename = FLOAT };
const abstract_type abstract_type_bool = { .typename = BOOL };
const abstract_type abstract_type_datetime = { .typename = DATETIME };
const abstract_type abstract_type_ref = { .typename = REF };

const abstract_type abstract_type_string_set =
    {
        .typename = SET,
        .child = &abstract_type_string
    };

const abstract_type abstract_type_ref_set =
    {
        .typename = SET,
        .child = &abstract_type_ref
    };

static const struct struct_member string_string_members[] =
{
    {
        .type = &abstract_type_string,
        .offset = offsetof(xen_string_string_map_contents, key)
    },
    {
        .type = &abstract_type_string,
        .offset = offsetof(xen_string_string_map_contents, val)
    }
};
const abstract_type abstract_type_string_string_map =
    {
        .typename = MAP,
        .struct_size = sizeof(xen_string_string_map_contents),
        .members = string_string_members
    };

static struct struct_member int_float_members[] =
{
    {
        .type = &abstract_type_int,
        .offset = offsetof(xen_int_float_map_contents, key)
    },
    {
        .type = &abstract_type_float,
        .offset = offsetof(xen_int_float_map_contents, val)
    }
};
const abstract_type abstract_type_int_float_map =
    {
        .typename = MAP,
        .struct_size = sizeof(xen_int_float_map_contents),
        .members = int_float_members
    };

static struct struct_member int_int_members[] =
{
    {
        .type = &abstract_type_int,
        .offset = offsetof(xen_int_int_map_contents, key)
    },
    {
        .type = &abstract_type_int,
        .offset = offsetof(xen_int_int_map_contents, val)
    }
};
const abstract_type abstract_type_int_int_map =
    {
        .typename = MAP,
        .struct_size = sizeof(xen_int_int_map_contents),
        .members = int_int_members
    };

static struct struct_member int_string_set_members[] =
{
    {
        .type = &abstract_type_int,
        .offset = offsetof(xen_int_string_set_map_contents, key)
    },
    {
        .type = &abstract_type_string_set,
        .offset = offsetof(xen_int_string_set_map_contents, val)
    }
};
const abstract_type abstract_type_int_string_set_map =
    {
        .typename = MAP,
        .struct_size = sizeof(xen_int_string_set_map_contents),
        .members = int_string_set_members
    };
