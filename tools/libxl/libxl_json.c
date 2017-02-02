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

#include "libxl_osdeps.h" /* must come before any other headers */

#include <math.h>

#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>

#include "libxl_internal.h"

/* #define DEBUG_ANSWER */

struct libxl__yajl_ctx {
    libxl__gc *gc;
    yajl_handle hand;
    libxl__json_object *head;
    libxl__json_object *current;
#ifdef DEBUG_ANSWER
    yajl_gen g;
#endif
};

#ifdef DEBUG_ANSWER
#if YAJL_VERSION < 20000
#  define DEBUG_GEN_ALLOC(ctx)                  \
    if ((ctx)->g == NULL) {                     \
        yajl_gen_config conf = { 1, "  " };     \
        (ctx)->g = yajl_gen_alloc(&conf, NULL); \
    }
#else  /* YAJL2 */
#  define DEBUG_GEN_ALLOC(ctx)                                    \
    if ((ctx)->g == NULL) {                                       \
        (ctx)->g = yajl_gen_alloc(NULL);                          \
        yajl_gen_config((ctx)->g, yajl_gen_beautify, 1);          \
        yajl_gen_config((ctx)->g, yajl_gen_indent_string, "  ");  \
    }
#endif
#  define DEBUG_GEN_FREE(ctx) \
    if ((ctx)->g) yajl_gen_free((ctx)->g)
#  define DEBUG_GEN(ctx, type)              yajl_gen_##type(ctx->g)
#  define DEBUG_GEN_VALUE(ctx, type, value) yajl_gen_##type(ctx->g, value)
#  define DEBUG_GEN_STRING(ctx, str, n)     yajl_gen_string(ctx->g, str, n)
#  define DEBUG_GEN_NUMBER(ctx, str, n)     yajl_gen_number(ctx->g, str, n)
#  define DEBUG_GEN_REPORT(yajl_ctx) \
    do { \
        const unsigned char *buf = NULL; \
        size_t len = 0; \
        yajl_gen_get_buf((yajl_ctx)->g, &buf, &len); \
        LIBXL__LOG(libxl__gc_owner((yajl_ctx)->gc), LIBXL__LOG_DEBUG,
		   "response:\n", buf); \
        yajl_gen_free((yajl_ctx)->g); \
        (yajl_ctx)->g = NULL; \
    } while (0)
#else
#  define DEBUG_GEN_ALLOC(ctx)                  ((void)0)
#  define DEBUG_GEN_FREE(ctx)                   ((void)0)
#  define DEBUG_GEN(ctx, type)                  ((void)0)
#  define DEBUG_GEN_VALUE(ctx, type, value)     ((void)0)
#  define DEBUG_GEN_STRING(ctx, value, length)  ((void)0)
#  define DEBUG_GEN_NUMBER(ctx, value, length)  ((void)0)
#  define DEBUG_GEN_REPORT(ctx)                 ((void)0)
#endif

/*
 * YAJL Helper
 */

yajl_gen_status libxl__yajl_gen_asciiz(yajl_gen hand, const char *str)
{
    return yajl_gen_string(hand, (const unsigned char *)str, strlen(str));
}

yajl_gen_status libxl__yajl_gen_enum(yajl_gen hand, const char *str)
{
    if (str)
        return libxl__yajl_gen_asciiz(hand, str);
    else
        return yajl_gen_null(hand);
}

/*
 * YAJL generators for builtin libxl types.
 */
yajl_gen_status libxl_defbool_gen_json(yajl_gen hand,
                                       libxl_defbool *db)
{
    return libxl__yajl_gen_asciiz(hand, libxl_defbool_to_string(*db));
}

int libxl__defbool_parse_json(libxl__gc *gc, const libxl__json_object *o,
                              libxl_defbool *p)
{
    const char *s;

    if (!libxl__json_object_is_string(o))
        return ERROR_FAIL;

    s = libxl__json_object_get_string(o);

    if (!strncmp(s, LIBXL__DEFBOOL_STR_DEFAULT,
                 strlen(LIBXL__DEFBOOL_STR_DEFAULT)))
        p->val = LIBXL__DEFBOOL_DEFAULT;
    else if (!strncmp(s, LIBXL__DEFBOOL_STR_TRUE,
                      strlen(LIBXL__DEFBOOL_STR_TRUE)))
        p->val = LIBXL__DEFBOOL_TRUE;
    else if (!strncmp(s, LIBXL__DEFBOOL_STR_FALSE,
                      strlen(LIBXL__DEFBOOL_STR_FALSE)))
        p->val = LIBXL__DEFBOOL_FALSE;
    else
        return ERROR_FAIL;

    return 0;
}

int libxl__bool_parse_json(libxl__gc *gc, const libxl__json_object *o,
                           bool *p)
{
    if (!libxl__json_object_is_bool(o))
        return ERROR_FAIL;

    *p = libxl__json_object_get_bool(o);

    return 0;
}

yajl_gen_status libxl_uuid_gen_json(yajl_gen hand,
                                    libxl_uuid *uuid)
{
    char buf[LIBXL_UUID_FMTLEN+1];
    snprintf(buf, sizeof(buf), LIBXL_UUID_FMT, LIBXL_UUID_BYTES((*uuid)));
    return yajl_gen_string(hand, (const unsigned char *)buf, LIBXL_UUID_FMTLEN);
}

int libxl__uuid_parse_json(libxl__gc *gc, const libxl__json_object *o,
                           libxl_uuid *p)
{
    if (!libxl__json_object_is_string(o))
        return ERROR_FAIL;

    return libxl_uuid_from_string(p, o->u.string);
}

yajl_gen_status libxl_bitmap_gen_json(yajl_gen hand,
                                      libxl_bitmap *bitmap)
{
    yajl_gen_status s;
    int i;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    libxl_for_each_bit(i, *bitmap) {
        if (libxl_bitmap_test(bitmap, i)) {
            s = yajl_gen_integer(hand, i);
            if (s != yajl_gen_status_ok) goto out;
        }
    }
    s = yajl_gen_array_close(hand);
out:
    return s;
}

int libxl__bitmap_parse_json(libxl__gc *gc, const libxl__json_object *o,
                            libxl_bitmap *p)
{
    int i;
    int size;
    const libxl__json_object *t;
    flexarray_t *array;

    if (!libxl__json_object_is_array(o))
        return ERROR_FAIL;

    array = libxl__json_object_get_array(o);
    if (!array->count) {
        libxl_bitmap_init(p);
        return 0;
    }

    t = libxl__json_array_get(o, array->count - 1);
    if (!libxl__json_object_is_integer(t))
        return ERROR_FAIL;
    size = libxl__json_object_get_integer(t) + 1;

    libxl_bitmap_alloc(CTX, p, size);

    for (i = 0; (t = libxl__json_array_get(o, i)); i++) {
        if (!libxl__json_object_is_integer(t))
            return ERROR_FAIL;

        libxl_bitmap_set(p, libxl__json_object_get_integer(t));
    }

    return 0;
}

yajl_gen_status libxl_key_value_list_gen_json(yajl_gen hand,
                                              libxl_key_value_list *pkvl)
{
    libxl_key_value_list kvl = *pkvl;
    yajl_gen_status s;
    int i;

    s = yajl_gen_map_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    if (!kvl) goto empty;

    for (i = 0; kvl[i] != NULL; i += 2) {
        s = libxl__yajl_gen_asciiz(hand, kvl[i]);
        if (s != yajl_gen_status_ok) goto out;
        if (kvl[i + 1])
            s = libxl__yajl_gen_asciiz(hand, kvl[i+1]);
        else
            s = yajl_gen_null(hand);
        if (s != yajl_gen_status_ok) goto out;
    }
empty:
    s = yajl_gen_map_close(hand);
out:
    return s;
}

int libxl__key_value_list_parse_json(libxl__gc *gc, const libxl__json_object *o,
                                     libxl_key_value_list *p)
{
    libxl__json_map_node *node = NULL;
    flexarray_t *maps = NULL;
    int i, size;
    libxl_key_value_list kvl;

    if (!libxl__json_object_is_map(o))
        return ERROR_FAIL;

    maps = libxl__json_object_get_map(o);
    size = maps->count * 2;
    kvl = *p = libxl__calloc(NOGC, size+1, sizeof(char *));

    for (i = 0; i < maps->count; i++) {
        int idx = i * 2;
        if (flexarray_get(maps, i, (void**)&node) != 0)
            return ERROR_FAIL;

        if (!libxl__json_object_is_string(node->obj) &&
            !libxl__json_object_is_null(node->obj))
            return ERROR_FAIL;

        kvl[idx] = libxl__strdup(NOGC, node->map_key);
        if (libxl__json_object_is_string(node->obj))
            kvl[idx+1] =
                libxl__strdup(NOGC, libxl__json_object_get_string(node->obj));
        else
            kvl[idx+1] = NULL;
    }

    return 0;
}

yajl_gen_status libxl_string_list_gen_json(yajl_gen hand, libxl_string_list *pl)
{
    libxl_string_list l = *pl;
    yajl_gen_status s;
    int i;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    if (!l) goto empty;

    for (i = 0; l[i] != NULL; i++) {
        s = libxl__yajl_gen_asciiz(hand, l[i]);
        if (s != yajl_gen_status_ok) goto out;
    }
empty:
    s = yajl_gen_array_close(hand);
out:
    return s;
}

int libxl__string_list_parse_json(libxl__gc *gc, const libxl__json_object *o,
                                  libxl_string_list *p)
{
    const libxl__json_object *t;
    libxl_string_list l;
    flexarray_t *array = NULL;
    int i, size;

    if (!libxl__json_object_is_array(o))
        return ERROR_FAIL;

    array = libxl__json_object_get_array(o);
    size = array->count;

    if (size == 0) {
        *p = NULL;
        return 0;
    }

    /* need one extra slot as sentinel */
    l = *p = libxl__calloc(NOGC, size + 1, sizeof(char *));

    for (i = 0; (t = libxl__json_array_get(o, i)); i++) {
        if (!libxl__json_object_is_string(t))
            return ERROR_FAIL;

        l[i] = libxl__strdup(NOGC, libxl__json_object_get_string(t));
    }

    return 0;
}

yajl_gen_status libxl_mac_gen_json(yajl_gen hand, libxl_mac *mac)
{
    char buf[LIBXL_MAC_FMTLEN+1];
    snprintf(buf, sizeof(buf), LIBXL_MAC_FMT, LIBXL_MAC_BYTES((*mac)));
    return yajl_gen_string(hand, (const unsigned char *)buf, LIBXL_MAC_FMTLEN);
}

int libxl__mac_parse_json(libxl__gc *gc, const libxl__json_object *o,
                          libxl_mac *p)
{
    if (!libxl__json_object_is_string(o))
        return ERROR_FAIL;

    return libxl__parse_mac(libxl__json_object_get_string(o), *p);
}

yajl_gen_status libxl_hwcap_gen_json(yajl_gen hand,
                                     libxl_hwcap *p)
{
    yajl_gen_status s;
    int i;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    for(i=0; i<4; i++) {
        s = yajl_gen_integer(hand, (*p)[i]);
        if (s != yajl_gen_status_ok) goto out;
    }
    s = yajl_gen_array_close(hand);
out:
    return s;
}

int libxl__hwcap_parse_json(libxl__gc *gc, const libxl__json_object *o,
                            libxl_hwcap *p)
{
    int i;

    if (!libxl__json_object_is_array(o))
        return ERROR_FAIL;

    for (i = 0; i<4; i++) {
        const libxl__json_object *t;

        t = libxl__json_array_get(o, i);
        if (!t || !libxl__json_object_is_integer(t))
            return ERROR_FAIL;

        (*p)[i] = libxl__json_object_get_integer(t);
    }

    return 0;
}

yajl_gen_status libxl_ms_vm_genid_gen_json(yajl_gen hand, libxl_ms_vm_genid *p)
{
    yajl_gen_status s;
    int i;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok)
        return s;

    for (i = 0; i < LIBXL_MS_VM_GENID_LEN; i++) {
        s = yajl_gen_integer(hand, p->bytes[i]);
        if (s != yajl_gen_status_ok)
            return s;
    }

    return yajl_gen_array_close(hand);
}

int libxl__ms_vm_genid_parse_json(libxl__gc *gc, const libxl__json_object *o,
                                  libxl_ms_vm_genid *p)
{
    unsigned int i;

    if (!libxl__json_object_is_array(o))
        return ERROR_FAIL;

    for (i = 0; i < LIBXL_MS_VM_GENID_LEN; i++) {
        const libxl__json_object *t;

        t = libxl__json_array_get(o, i);
        if (!t || !libxl__json_object_is_integer(t))
            return ERROR_FAIL;

        p->bytes[i] = libxl__json_object_get_integer(t);
    }

    return 0;
}

yajl_gen_status libxl__string_gen_json(yajl_gen hand,
                                       const char *p)
{
    if (p)
        return libxl__yajl_gen_asciiz(hand, p);
    else
        return yajl_gen_null(hand);
}

int libxl__string_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             char **p)
{
    if (!libxl__json_object_is_string(o) && !libxl__json_object_is_null(o))
        return ERROR_FAIL;

    if (libxl__json_object_is_null(o))
        *p = NULL;
    else
        *p = libxl__strdup(NOGC, libxl__json_object_get_string(o));

    return 0;
}

/*
 * libxl__json_object helper functions
 */

libxl__json_object *libxl__json_object_alloc(libxl__gc *gc,
                                             libxl__json_node_type type)
{
    libxl__json_object *obj;

    obj = libxl__zalloc(gc, sizeof(*obj));

    obj->type = type;

    if (type == JSON_MAP || type == JSON_ARRAY) {
        flexarray_t *array = flexarray_make(gc, 1, 1);
        if (type == JSON_MAP)
            obj->u.map = array;
        else
            obj->u.array = array;
    }

    return obj;
}

int libxl__json_object_append_to(libxl__gc *gc, libxl__json_object *obj,
                                 libxl__yajl_ctx *ctx)
{
    libxl__json_object *dst = ctx->current;

    if (dst) {
        switch (dst->type) {
        case JSON_MAP: {
            libxl__json_map_node *last;

            if (dst->u.map->count == 0) {
                LIBXL__LOG(libxl__gc_owner(gc), LIBXL__LOG_ERROR,
                           "Try to add a value to an empty map (with no key)");
                return ERROR_FAIL;
            }
            flexarray_get(dst->u.map, dst->u.map->count - 1, (void**)&last);
            last->obj = obj;
            break;
        }
        case JSON_ARRAY:
            flexarray_append(dst->u.array, obj);
            break;
        default:
            LIBXL__LOG(libxl__gc_owner(gc), LIBXL__LOG_ERROR,
                       "Try append an object is not a map/array (%i)",
                       dst->type);
            return ERROR_FAIL;
        }
    }

    obj->parent = dst;

    if (libxl__json_object_is_map(obj) || libxl__json_object_is_array(obj))
        ctx->current = obj;
    if (ctx->head == NULL)
        ctx->head = obj;

    return 0;
}

void libxl__json_object_free(libxl__gc *gc, libxl__json_object *obj)
{
    int idx = 0;

    if (obj == NULL)
        return;
    switch (obj->type) {
    case JSON_STRING:
    case JSON_NUMBER:
        free(obj->u.string);
        break;
    case JSON_MAP: {
        libxl__json_map_node *node = NULL;

        for (idx = 0; idx < obj->u.map->count; idx++) {
            if (flexarray_get(obj->u.map, idx, (void**)&node) != 0)
                break;
            libxl__json_object_free(gc, node->obj);
            free(node->map_key);
            free(node);
            node = NULL;
        }
        flexarray_free(obj->u.map);
        break;
    }
    case JSON_ARRAY: {
        libxl__json_object *node = NULL;

        for (idx = 0; idx < obj->u.array->count; idx++) {
            if (flexarray_get(obj->u.array, idx, (void**)&node) != 0)
                break;
            libxl__json_object_free(gc, node);
            node = NULL;
        }
        flexarray_free(obj->u.array);
        break;
    }
    default:
        break;
    }
    free(obj);
}

libxl__json_object *libxl__json_array_get(const libxl__json_object *o, int i)
{
    flexarray_t *array = NULL;
    libxl__json_object *obj = NULL;

    if ((array = libxl__json_object_get_array(o)) == NULL) {
        return NULL;
    }

    if (i >= array->count)
        return NULL;

    if (flexarray_get(array, i, (void**)&obj) != 0)
        return NULL;

    return obj;
}

libxl__json_map_node *libxl__json_map_node_get(const libxl__json_object *o,
                                               int i)
{
    flexarray_t *array = NULL;
    libxl__json_map_node *obj = NULL;

    if ((array = libxl__json_object_get_map(o)) == NULL) {
        return NULL;
    }

    if (i >= array->count)
        return NULL;

    if (flexarray_get(array, i, (void**)&obj) != 0)
        return NULL;

    return obj;
}

const libxl__json_object *libxl__json_map_get(const char *key,
                                          const libxl__json_object *o,
                                          libxl__json_node_type expected_type)
{
    flexarray_t *maps = NULL;
    int idx = 0;

    if (libxl__json_object_is_map(o)) {
        libxl__json_map_node *node = NULL;

        maps = o->u.map;
        for (idx = 0; idx < maps->count; idx++) {
            if (flexarray_get(maps, idx, (void**)&node) != 0)
                return NULL;
            if (strcmp(key, node->map_key) == 0) {
                if (expected_type == JSON_ANY
                    || (node->obj && (node->obj->type & expected_type))) {
                    return node->obj;
                } else {
                    return NULL;
                }
            }
        }
    }
    return NULL;
}

yajl_status libxl__json_object_to_yajl_gen(libxl__gc *gc,
                                           yajl_gen hand,
                                           libxl__json_object *obj)
{
    int idx = 0;
    yajl_status rc;

#define CONVERT_YAJL_GEN_TO_STATUS(gen) \
    ((gen) == yajl_gen_status_ok ? yajl_status_ok : yajl_status_error)

    switch (obj->type) {
    case JSON_NULL:
        return CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_null(hand));
    case JSON_BOOL:
        return CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_bool(hand, obj->u.b));
    case JSON_INTEGER:
        return CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_integer(hand, obj->u.i));
    case JSON_DOUBLE:
        return CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_double(hand, obj->u.d));
    case JSON_NUMBER:
        return CONVERT_YAJL_GEN_TO_STATUS(
                  yajl_gen_number(hand, obj->u.string, strlen(obj->u.string)));
    case JSON_STRING:
        return CONVERT_YAJL_GEN_TO_STATUS(
                        libxl__yajl_gen_asciiz(hand, obj->u.string));
    case JSON_MAP: {
        libxl__json_map_node *node = NULL;

        rc = CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_map_open(hand));
        if (rc != yajl_status_ok)
            return rc;
        for (idx = 0; idx < obj->u.map->count; idx++) {
            if (flexarray_get(obj->u.map, idx, (void**)&node) != 0)
                break;

            rc = CONVERT_YAJL_GEN_TO_STATUS(
                            libxl__yajl_gen_asciiz(hand, node->map_key));
            if (rc != yajl_status_ok)
                return rc;
            rc = libxl__json_object_to_yajl_gen(gc, hand, node->obj);
            if (rc != yajl_status_ok)
                return rc;
        }
        return CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_map_close(hand));
    }
    case JSON_ARRAY: {
        libxl__json_object *node = NULL;

        rc = CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_array_open(hand));
        if (rc != yajl_status_ok)
            return rc;
        for (idx = 0; idx < obj->u.array->count; idx++) {
            if (flexarray_get(obj->u.array, idx, (void**)&node) != 0)
                break;
            rc = libxl__json_object_to_yajl_gen(gc, hand, node);
            if (rc != yajl_status_ok)
                return rc;
        }
        return CONVERT_YAJL_GEN_TO_STATUS(yajl_gen_array_close(hand));
    }
    case JSON_ANY:
        /* JSON_ANY is not a valid value for obj->type. */
        ;
    }
    abort();
#undef CONVERT_YAJL_GEN_TO_STATUS
}


/*
 * JSON callbacks
 */

static int json_callback_null(void *opaque)
{
    libxl__yajl_ctx *ctx = opaque;
    libxl__json_object *obj;

    DEBUG_GEN(ctx, null);

    obj = libxl__json_object_alloc(ctx->gc, JSON_NULL);

    if (libxl__json_object_append_to(ctx->gc, obj, ctx))
        return 0;

    return 1;
}

static int json_callback_boolean(void *opaque, int boolean)
{
    libxl__yajl_ctx *ctx = opaque;
    libxl__json_object *obj;

    DEBUG_GEN_VALUE(ctx, bool, boolean);

    obj = libxl__json_object_alloc(ctx->gc, JSON_BOOL);
    obj->u.b = boolean;

    if (libxl__json_object_append_to(ctx->gc, obj, ctx))
        return 0;

    return 1;
}

static bool is_decimal(const char *s, unsigned len)
{
    const char *end = s + len;
    for (; s < end; s++) {
        if (*s == '.')
            return true;
    }
    return false;
}

static int json_callback_number(void *opaque, const char *s, libxl_yajl_length len)
{
    libxl__yajl_ctx *ctx = opaque;
    libxl__json_object *obj = NULL;
    char *t = NULL;

    DEBUG_GEN_NUMBER(ctx, s, len);

    if (is_decimal(s, len)) {
        double d = strtod(s, NULL);

        if ((d == HUGE_VALF || d == HUGE_VALL) && errno == ERANGE) {
            goto error;
        }

        obj = libxl__json_object_alloc(ctx->gc, JSON_DOUBLE);
        obj->u.d = d;
    } else {
        long long i = strtoll(s, NULL, 10);

        if ((i == LLONG_MIN || i == LLONG_MAX) && errno == ERANGE) {
            goto error;
        }

        obj = libxl__json_object_alloc(ctx->gc, JSON_INTEGER);
        obj->u.i = i;
    }
    goto out;

error:
    /* If the conversion fail, we just store the original string. */
    obj = libxl__json_object_alloc(ctx->gc, JSON_NUMBER);

    t = libxl__zalloc(ctx->gc, len + 1);
    strncpy(t, s, len);
    t[len] = 0;

    obj->u.string = t;

out:
    if (libxl__json_object_append_to(ctx->gc, obj, ctx))
        return 0;

    return 1;
}

static int json_callback_string(void *opaque, const unsigned char *str,
                                libxl_yajl_length len)
{
    libxl__yajl_ctx *ctx = opaque;
    char *t = NULL;
    libxl__json_object *obj = NULL;

    t = libxl__zalloc(ctx->gc, len + 1);

    DEBUG_GEN_STRING(ctx, str, len);

    strncpy(t, (const char *) str, len);
    t[len] = 0;

    obj = libxl__json_object_alloc(ctx->gc, JSON_STRING);
    obj->u.string = t;

    if (libxl__json_object_append_to(ctx->gc, obj, ctx))
        return 0;

    return 1;
}

static int json_callback_map_key(void *opaque, const unsigned char *str,
                                 libxl_yajl_length len)
{
    libxl__yajl_ctx *ctx = opaque;
    char *t = NULL;
    libxl__json_object *obj = ctx->current;
    libxl__gc *gc = ctx->gc;

    t = libxl__zalloc(gc, len + 1);

    DEBUG_GEN_STRING(ctx, str, len);

    strncpy(t, (const char *) str, len);
    t[len] = 0;

    if (libxl__json_object_is_map(obj)) {
        libxl__json_map_node *node;

        GCNEW(node);
        node->map_key = t;
        node->obj = NULL;

        flexarray_append(obj->u.map, node);
    } else {
        LIBXL__LOG(libxl__gc_owner(ctx->gc), LIBXL__LOG_ERROR,
                   "Current json object is not a map");
        return 0;
    }

    return 1;
}

static int json_callback_start_map(void *opaque)
{
    libxl__yajl_ctx *ctx = opaque;
    libxl__json_object *obj = NULL;

    DEBUG_GEN(ctx, map_open);

    obj = libxl__json_object_alloc(ctx->gc, JSON_MAP);

    if (libxl__json_object_append_to(ctx->gc, obj, ctx))
        return 0;

    return 1;
}

static int json_callback_end_map(void *opaque)
{
    libxl__yajl_ctx *ctx = opaque;

    DEBUG_GEN(ctx, map_close);

    if (ctx->current) {
        ctx->current = ctx->current->parent;
    } else {
        LIBXL__LOG(libxl__gc_owner(ctx->gc), LIBXL__LOG_ERROR,
                   "No current libxl__json_object, cannot use his parent.");
        return 0;
    }

    return 1;
}

static int json_callback_start_array(void *opaque)
{
    libxl__yajl_ctx *ctx = opaque;
    libxl__json_object *obj = NULL;

    DEBUG_GEN(ctx, array_open);

    obj = libxl__json_object_alloc(ctx->gc, JSON_ARRAY);

    if (libxl__json_object_append_to(ctx->gc, obj, ctx))
        return 0;

    return 1;
}

static int json_callback_end_array(void *opaque)
{
    libxl__yajl_ctx *ctx = opaque;

    DEBUG_GEN(ctx, array_close);

    if (ctx->current) {
        ctx->current = ctx->current->parent;
    } else {
        LIBXL__LOG(libxl__gc_owner(ctx->gc), LIBXL__LOG_ERROR,
                   "No current libxl__json_object, cannot use his parent.");
        return 0;
    }

    return 1;
}

static yajl_callbacks callbacks = {
    json_callback_null,
    json_callback_boolean,
    NULL,
    NULL,
    json_callback_number,
    json_callback_string,
    json_callback_start_map,
    json_callback_map_key,
    json_callback_end_map,
    json_callback_start_array,
    json_callback_end_array
};

static void yajl_ctx_free(libxl__yajl_ctx *yajl_ctx)
{
    if (yajl_ctx->hand) {
        yajl_free(yajl_ctx->hand);
        yajl_ctx->hand = NULL;
    }
    DEBUG_GEN_FREE(yajl_ctx);
}

libxl__json_object *libxl__json_parse(libxl__gc *gc, const char *s)
{
    yajl_status status;
    libxl__yajl_ctx yajl_ctx;
    libxl__json_object *o = NULL;
    unsigned char *str = NULL;

    memset(&yajl_ctx, 0, sizeof (yajl_ctx));
    yajl_ctx.gc = gc;

    DEBUG_GEN_ALLOC(&yajl_ctx);

    if (yajl_ctx.hand == NULL) {
        yajl_ctx.hand = libxl__yajl_alloc(&callbacks, NULL, &yajl_ctx);
    }
    status = yajl_parse(yajl_ctx.hand, (const unsigned char *)s, strlen(s));
    if (status != yajl_status_ok)
        goto out;

    status = yajl_complete_parse(yajl_ctx.hand);
    if (status != yajl_status_ok)
        goto out;

    o = yajl_ctx.head;

    DEBUG_GEN_REPORT(&yajl_ctx);

    yajl_ctx.head = NULL;

    yajl_ctx_free(&yajl_ctx);
    return o;

out:
    str = yajl_get_error(yajl_ctx.hand, 1, (const unsigned char*)s, strlen(s));

    LIBXL__LOG(libxl__gc_owner(gc), LIBXL__LOG_ERROR, "yajl error: %s", str);
    yajl_free_error(yajl_ctx.hand, str);
    yajl_ctx_free(&yajl_ctx);
    return NULL;
}

static const char *yajl_gen_status_to_string(yajl_gen_status s)
{
        switch (s) {
        case yajl_gen_status_ok: abort();
        case yajl_gen_keys_must_be_strings:
            return "keys must be strings";
        case yajl_max_depth_exceeded:
            return "max depth exceeded";
        case yajl_gen_in_error_state:
            return "in error state";
        case yajl_gen_generation_complete:
            return "generation complete";
        case yajl_gen_invalid_number:
            return "invalid number";
#if 0 /* This is in the docs but not implemented in the version I am running. */
        case yajl_gen_no_buf:
            return "no buffer";
        case yajl_gen_invalid_string:
            return "invalid string";
#endif
        default:
            return "unknown error";
        }
}

char *libxl__object_to_json(libxl_ctx *ctx, const char *type,
                            libxl__gen_json_callback gen, void *p)
{
    const unsigned char *buf;
    char *ret = NULL;
    libxl_yajl_length len = 0;
    yajl_gen_status s;
    yajl_gen hand;

    hand = libxl_yajl_gen_alloc(NULL);
    if (!hand)
        return NULL;

    s = gen(hand, p);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_get_buf(hand, &buf, &len);
    if (s != yajl_gen_status_ok)
        goto out;
    ret = strdup((const char *)buf);

out:
    yajl_gen_free(hand);

    if (s != yajl_gen_status_ok) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "unable to convert %s to JSON representation. "
                   "YAJL error code %d: %s", type,
                   s, yajl_gen_status_to_string(s));
    } else if (!ret) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "unable to allocate space for to JSON representation of %s",
                   type);
    }

    return ret;
}

yajl_gen_status libxl__uint64_gen_json(yajl_gen hand, uint64_t val)
{
    char *num;
    int len;
    yajl_gen_status s;


    len = asprintf(&num, "%"PRIu64, val);
    if (len == -1) {
        s = yajl_gen_in_error_state;
        goto out;
    }

    s = yajl_gen_number(hand, num, len);

    free(num);

out:
    return s;
}

int libxl__object_from_json(libxl_ctx *ctx, const char *type,
                            libxl__json_parse_callback parse,
                            void *p, const char *s)
{
    GC_INIT(ctx);
    libxl__json_object *o;
    int rc;

    o = libxl__json_parse(gc, s);
    if (!o) {
        LOG(ERROR,
            "unable to generate libxl__json_object from JSON representation of %s.",
            type);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = parse(gc, o, p);
    if (rc) {
        LOG(ERROR, "unable to convert libxl__json_object to %s. (rc=%d)", type, rc);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl__int_parse_json(libxl__gc *gc, const libxl__json_object *o,
                          void *p)
{
    long long i;

    if (!libxl__json_object_is_integer(o))
        return ERROR_FAIL;

    i = libxl__json_object_get_integer(o);

    if (i > INT_MAX || i < INT_MIN)
        return ERROR_FAIL;

    *((int *)p) = i;

    return 0;
}

/* Macro to generate:
 *  libxl__uint8_parse_json
 *  libxl__uint16_parse_json
 *  libxl__uint32_parse_json
 */
#define PARSE_UINT(width)                                               \
    int libxl__uint ## width ## _parse_json(libxl__gc *gc,              \
                                            const libxl__json_object *o,\
                                            void *p)                    \
    {                                                                   \
        long long i;                                                    \
                                                                        \
        if (!libxl__json_object_is_integer(o))                          \
            return ERROR_FAIL;                                          \
                                                                        \
        i = libxl__json_object_get_integer(o);                          \
                                                                        \
        if (i < 0 || i > UINT ## width ## _MAX)                         \
            return ERROR_FAIL;                                          \
                                                                        \
        *((uint ## width ## _t *)p) = i;                                \
                                                                        \
        return 0;                                                       \
    }

PARSE_UINT(8);
PARSE_UINT(16);
PARSE_UINT(32);

int libxl__uint64_parse_json(libxl__gc *gc, const libxl__json_object *o,
                             void *p)
{
    if (!libxl__json_object_is_integer(o) &&
        !libxl__json_object_is_number(o))
        return ERROR_FAIL;

    if (libxl__json_object_is_integer(o)) {
        long long i = libxl__json_object_get_integer(o);

        if (i < 0)
            return ERROR_FAIL;

        *((uint64_t *)p) = i;
    } else {
        const char *s;
        unsigned long long i;
        int saved_errno = errno;

        s = libxl__json_object_get_number(o);

        errno = 0;
        i = strtoull(s, NULL, 10);

        if (i == ULLONG_MAX && errno == ERANGE)
            return ERROR_FAIL;

        errno = saved_errno;
        *((uint64_t *)p) = i;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
