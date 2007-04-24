/*
 * Copyright (c) 2006 XenSource, Inc.
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

#ifndef XEN_INTERNAL_H
#define XEN_INTERNAL_H


#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "xen_common.h"


enum abstract_typename
{
  VOID,
  STRING,
  INT,
  FLOAT,
  BOOL,
  DATETIME,
  SET,
  MAP,
  STRUCT,
  REF,
  ENUM,
  ENUMSET
};


typedef struct
{
    size_t size;
    void *contents[];
} arbitrary_set;


typedef struct struct_member struct_member;


typedef struct abstract_type
{
    enum abstract_typename typename;
    const struct abstract_type *child;
    const char * (*enum_marshaller)(int);
    int (*enum_demarshaller)(xen_session *, const char *);
    size_t struct_size;
    size_t member_count;
    const struct_member *members;
} abstract_type;


struct struct_member
{
    const char *key;
    const struct abstract_type *type;
    int offset;
};


extern const abstract_type abstract_type_string;
extern const abstract_type abstract_type_int;
extern const abstract_type abstract_type_float;
extern const abstract_type abstract_type_bool;
extern const abstract_type abstract_type_datetime;
extern const abstract_type abstract_type_ref;

extern const abstract_type abstract_type_string_set;
extern const abstract_type abstract_type_ref_set;

extern const abstract_type abstract_type_string_string_map;
extern const abstract_type abstract_type_int_float_map;
extern const abstract_type abstract_type_int_int_map;
extern const abstract_type abstract_type_int_string_set_map;


typedef struct abstract_value
{
    const abstract_type *type;
    union
    {
        const char *string_val;
        int64_t int_val;
        int enum_val;
        double float_val;
        bool bool_val;
        arbitrary_set *set_val;
        void *struct_val;
        time_t datetime_val;
    } u;
} abstract_value;


extern void
xen_call_(xen_session *s, const char *method_name, abstract_value params[],
          int param_count, const abstract_type *result_type, void *value);


#define XEN_CALL_(method_name__)                                \
    xen_call_(session, method_name__, param_values,             \
              sizeof(param_values) / sizeof(param_values[0]),   \
              &result_type, result)                             \


extern char *
xen_strdup_(const char *in);


extern int
xen_enum_lookup_(xen_session *session, const char *str,
                 const char **lookup_table, int n);

#define ENUM_LOOKUP(session__, str__, lookup_table__)   \
    xen_enum_lookup_(session__, str__, lookup_table__,  \
                     sizeof(lookup_table__) /           \
                     sizeof(lookup_table__[0]))         \

#define XEN_ALLOC(type__)                       \
type__ *                                        \
type__ ## _alloc()                              \
{                                               \
    return calloc(1, sizeof(type__));           \
}                                               \


#define XEN_FREE(type__)                        \
void                                            \
type__ ## _free(type__ handle)                  \
{                                               \
    free(handle);                               \
}                                               \


#define XEN_SET_ALLOC_FREE(type__)                                      \
type__ ## _set *                                                        \
type__ ## _set_alloc(size_t size)                                       \
{                                                                       \
    type__ ## _set *result = calloc(1, sizeof(type__ ## _set) +         \
                                    size * sizeof(type__));             \
    result->size = size;                                                \
    return result;                                                      \
}                                                                       \
                                                                        \
void                                                                    \
type__ ## _set_free(type__ ## _set *set)                                \
{                                                                       \
    if (set == NULL)                                                    \
    {                                                                   \
        return;                                                         \
    }                                                                   \
    size_t n = set->size;                                               \
    for (size_t i = 0; i < n; i++)                                      \
    {                                                                   \
       type__ ## _free(set->contents[i]);                               \
    }                                                                   \
                                                                        \
    free(set);                                                          \
}                                                                       \


#define XEN_RECORD_OPT_FREE(type__)                     \
void                                                    \
type__ ## _record_opt_free(type__ ## _record_opt *opt)  \
{                                                       \
    if (opt == NULL)                                    \
    {                                                   \
        return;                                         \
    }                                                   \
    if (opt->is_record)                                 \
    {                                                   \
        type__ ## _record_free(opt->u.record);          \
    }                                                   \
    else                                                \
    {                                                   \
        type__ ## _free(opt->u.handle);                 \
    }                                                   \
    free(opt);                                          \
}                                                       \


#endif
