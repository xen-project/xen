/*
 * Copyright (C) 2011      Citrix Ltd.
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

#ifndef LIBXL_JSON_H
#define LIBXL_JSON_H

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#ifdef HAVE_YAJL_YAJL_VERSION_H
#  include <yajl/yajl_version.h>
#endif

typedef struct libxl__gc libxl__gc;
typedef struct libxl__json_object libxl__json_object;

yajl_gen_status libxl__uint64_gen_json(yajl_gen hand, uint64_t val);
yajl_gen_status libxl_defbool_gen_json(yajl_gen hand, libxl_defbool *p);
int libxl_defbool_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             libxl_defbool *p);
int libxl__bool_parse_json(libxl__gc *gc, const libxl__json_object *o,
                           bool *p);
yajl_gen_status libxl_uuid_gen_json(yajl_gen hand, libxl_uuid *p);
int libxl_uuid_parse_json(libxl__gc *gc, const libxl__json_object *o,
                          libxl_uuid *p);
yajl_gen_status libxl_mac_gen_json(yajl_gen hand, libxl_mac *p);
int libxl_mac_parse_json(libxl__gc *gc, const libxl__json_object *o,
                         libxl_mac *p);
yajl_gen_status libxl_bitmap_gen_json(yajl_gen hand, libxl_bitmap *p);
int libxl_bitmap_parse_json(libxl__gc *gc, const libxl__json_object *o,
                            libxl_bitmap *p);
yajl_gen_status libxl_cpuid_policy_list_gen_json(yajl_gen hand,
                                                 libxl_cpuid_policy_list *p);
int libxl_cpuid_policy_list_parse_json(libxl__gc *gc,
                                       const libxl__json_object *o,
                                       libxl_cpuid_policy_list *p);
yajl_gen_status libxl_string_list_gen_json(yajl_gen hand, libxl_string_list *p);
int libxl_string_list_parse_json(libxl__gc *gc, const libxl__json_object *o,
                                 libxl_string_list *p);
yajl_gen_status libxl_key_value_list_gen_json(yajl_gen hand,
                                              libxl_key_value_list *p);
int libxl_key_value_list_parse_json(libxl__gc *gc,
                                    const libxl__json_object *o,
                                    libxl_key_value_list *p);
yajl_gen_status libxl_hwcap_gen_json(yajl_gen hand, libxl_hwcap *p);
int libxl_hwcap_parse_json(libxl__gc *gc, const libxl__json_object *o,
                           libxl_hwcap *p);
int libxl__int_parse_json(libxl__gc *gc, const libxl__json_object *o,
                          void *p);
int libxl__uint8_parse_json(libxl__gc *gc, const libxl__json_object *o,
                            void *p);
int libxl__uint16_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             void *p);
int libxl__uint32_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             void *p);
int libxl__uint64_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             void *p);
int libxl__string_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             char **p);

#include <_libxl_types_json.h>

/* YAJL version check */
#if defined(YAJL_MAJOR) && (YAJL_MAJOR > 1)
#  define HAVE_YAJL_V2 1
#endif

#ifdef HAVE_YAJL_V2

typedef size_t libxl_yajl_length;

static inline yajl_handle libxl__yajl_alloc(const yajl_callbacks *callbacks,
                                            yajl_alloc_funcs *allocFuncs,
                                            void *ctx)
{
    return yajl_alloc(callbacks, allocFuncs, ctx);
}

static inline yajl_gen libxl_yajl_gen_alloc(const yajl_alloc_funcs *allocFuncs)
{
    yajl_gen g;
    g = yajl_gen_alloc(allocFuncs);
    if (g)
        yajl_gen_config(g, yajl_gen_beautify, 1);
    return g;
}

#else /* !HAVE_YAJL_V2 */

#define yajl_complete_parse yajl_parse_complete

typedef unsigned int libxl_yajl_length;

static inline yajl_handle libxl__yajl_alloc(const yajl_callbacks *callbacks,
                                            const yajl_alloc_funcs *allocFuncs,
                                            void *ctx)
{
    yajl_parser_config cfg = {
        .allowComments = 1,
        .checkUTF8 = 1,
    };
    return yajl_alloc(callbacks, &cfg, allocFuncs, ctx);
}

static inline yajl_gen libxl_yajl_gen_alloc(const yajl_alloc_funcs *allocFuncs)
{
    yajl_gen_config conf = { 1, "    " };
    return yajl_gen_alloc(&conf, allocFuncs);
}

#endif /* !HAVE_YAJL_V2 */

yajl_gen_status libxl_domain_config_gen_json(yajl_gen hand,
                                             libxl_domain_config *p);

#endif /* LIBXL_JSON_H */
