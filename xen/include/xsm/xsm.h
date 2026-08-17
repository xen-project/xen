/*
 *  This file contains the XSM hook definitions for Xen.
 *
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __XSM_H__
#define __XSM_H__

#include <xen/alternative-call.h>
#include <xen/sched.h>

/* policy magic number (defined by XSM_MAGIC) */
typedef uint32_t xsm_magic_t;

#ifdef CONFIG_XSM_FLASK
#define XSM_MAGIC 0xf97cff8cU
#else
#define XSM_MAGIC 0x0U
#endif

/*
 * These annotations are used by callers and in dummy.h to document the
 * default actions of XSM hooks. They should be compiled out otherwise.
 */
enum xsm_default {
    XSM_HOOK,     /* Guests can normally access the hypercall */
    XSM_DM_PRIV,  /* Device model can perform on its target domain */
    XSM_TARGET,   /* Can perform on self or your target domain */
    XSM_PRIV,     /* Privileged - normally restricted to dom0 */
    XSM_XS_PRIV,  /* Xenstore domain - can do some privileged operations */
    XSM_OTHER     /* Something more complex */
};
typedef enum xsm_default xsm_default_t;

#ifdef CONFIG_X86
#define XSM_MMU_UPDATE_READ      1
#define XSM_MMU_UPDATE_WRITE     2
#define XSM_MMU_NORMAL_UPDATE    4
#define XSM_MMU_MACHPHYS_UPDATE  8
#endif /* CONFIG_X86 */

/*
 * !!! WARNING !!!
 *
 * For simplicity, xsm_fixup_ops() expects that this structure is made
 * exclusively of function pointers to non-init functions.  Think carefully
 * before deviating from the pattern.
 *
 * !!! WARNING !!!
 */
struct xsm_ops {
    int (*set_system_active)(void);
    void (*security_domaininfo)(struct domain *d,
                                struct xen_domctl_getdomaininfo *info);

#define XSM_HOOK0(rtype, name) rtype (*name)(void);
#define XSM_HOOK1(rtype, name, type1) \
    rtype (*name)(type1 arg1);
#define XSM_HOOK2(rtype, name, type1, type2) \
    rtype (*name)(type1 arg1, type2 arg2);
#define XSM_HOOK3(rtype, name, type1, type2, type3) \
    rtype (*name)(type1 arg1, type2 arg2, type3 arg3);
#define XSM_HOOK4(rtype, name, type1, type2, type3, type4) \
    rtype (*name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4);
#define XSM_HOOK5(rtype, name, type1, type2, type3, type4, type5) \
    rtype (*name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5);

#include "hooks.h"

    void (*evtchn_close_post)(struct evtchn *chn);

    int (*alloc_security_domain)(struct domain *d);
    void (*free_security_domain)(struct domain *d);
    int (*alloc_security_evtchns)(struct evtchn chn[], unsigned int nr);
    void (*free_security_evtchns)(struct evtchn chn[], unsigned int nr);
    char *(*show_security_evtchn)(struct domain *d, const struct evtchn *chn);

    char *(*show_irq_sid)(int irq);

#ifdef CONFIG_ARGO
    int (*argo_enable)(const struct domain *d);
    int (*argo_register_single_source)(const struct domain *d,
                                       const struct domain *t);
    int (*argo_register_any_source)(const struct domain *d);
    int (*argo_send)(const struct domain *d, const struct domain *t);
#endif
};

#ifdef CONFIG_XSM

extern struct xsm_ops xsm_ops;

#ifndef XSM_NO_WRAPPERS

static inline int xsm_set_system_active(void)
{
    return alternative_call(xsm_ops.set_system_active);
}

static inline void xsm_security_domaininfo(
    struct domain *d, struct xen_domctl_getdomaininfo *info)
{
    alternative_vcall(xsm_ops.security_domaininfo, d, info);
}

#define XSM_ALT_void alternative_vcall
#define XSM_ALT_int  return alternative_call

#define XSM_HOOK0(rtype, name) \
static inline rtype xsm_ ## name(xsm_default_t def) \
{ \
    XSM_ALT_ ## rtype(xsm_ops.name); \
}

#define XSM_HOOK1(rtype, name, type1) \
static inline rtype xsm_ ## name(xsm_default_t def, type1 arg1) \
{ \
    XSM_ALT_ ## rtype(xsm_ops.name, arg1); \
}

#define XSM_HOOK2(rtype, name, type1, type2) \
static inline rtype xsm_ ## name( \
    xsm_default_t def, type1 arg1, type2 arg2) \
{ \
    XSM_ALT_ ## rtype(xsm_ops.name, arg1, arg2); \
}

#define XSM_HOOK3(rtype, name, type1, type2, type3) \
static inline rtype xsm_ ## name( \
    xsm_default_t def, type1 arg1, type2 arg2, type3 arg3) \
{ \
    XSM_ALT_ ## rtype(xsm_ops.name, arg1, arg2, arg3); \
}

#define XSM_HOOK4(rtype, name, type1, type2, type3, type4) \
static inline rtype xsm_ ## name( \
    xsm_default_t def, type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
    XSM_ALT_ ## rtype(xsm_ops.name, arg1, arg2, arg3, arg4); \
}

#define XSM_HOOK5(rtype, name, type1, type2, type3, type4, type5) \
static inline rtype xsm_ ## name( \
    xsm_default_t def, type1 arg1, type2 arg2, type3 arg3, type4 arg4, \
    type5 arg5) \
{ \
    XSM_ALT_ ## rtype(xsm_ops.name, arg1, arg2, arg3, arg4, arg5); \
}

#include "hooks.h"

static inline void xsm_evtchn_close_post(struct evtchn *chn)
{
    alternative_vcall(xsm_ops.evtchn_close_post, chn);
}

static inline int xsm_alloc_security_domain(struct domain *d)
{
    return alternative_call(xsm_ops.alloc_security_domain, d);
}

static inline void xsm_free_security_domain(struct domain *d)
{
    alternative_vcall(xsm_ops.free_security_domain, d);
}

static inline int xsm_alloc_security_evtchns(
    struct evtchn *chn, unsigned int nr)
{
    return alternative_call(xsm_ops.alloc_security_evtchns, chn, nr);
}

static inline void xsm_free_security_evtchns(
    struct evtchn *chn, unsigned int nr)
{
    alternative_vcall(xsm_ops.free_security_evtchns, chn, nr);
}

static inline char *xsm_show_security_evtchn(
    struct domain *d, const struct evtchn *chn)
{
    return alternative_call(xsm_ops.show_security_evtchn, d, chn);
}

static inline char *xsm_show_irq_sid(int irq)
{
    return alternative_call(xsm_ops.show_irq_sid, irq);
}

#ifdef CONFIG_ARGO
static inline int xsm_argo_enable(const struct domain *d)
{
    return alternative_call(xsm_ops.argo_enable, d);
}

static inline int xsm_argo_register_single_source(
    const struct domain *d, const struct domain *t)
{
    return alternative_call(xsm_ops.argo_register_single_source, d, t);
}

static inline int xsm_argo_register_any_source(const struct domain *d)
{
    return alternative_call(xsm_ops.argo_register_any_source, d);
}

static inline int xsm_argo_send(const struct domain *d, const struct domain *t)
{
    return alternative_call(xsm_ops.argo_send, d, t);
}

#endif /* CONFIG_ARGO */

#endif /* XSM_NO_WRAPPERS */

#ifdef CONFIG_MULTIBOOT
struct boot_info;
int xsm_multiboot_init(struct boot_info *bi);
int xsm_multiboot_policy_init(
    struct boot_info *bi, void **policy_buffer, size_t *policy_size);
#endif

#ifdef CONFIG_HAS_DEVICE_TREE_DISCOVERY
/*
 * Initialize XSM
 *
 * On success, return 1 if using SILO mode else 0.
 */
int xsm_dt_init(void);
int xsm_dt_policy_init(void **policy_buffer, size_t *policy_size);
bool has_xsm_magic(paddr_t start);
#endif

void xsm_fixup_ops(struct xsm_ops *ops);

#ifdef CONFIG_XSM_FLASK
extern const struct xsm_ops *flask_init(const void *policy_buffer,
                                        size_t policy_size);
#else
static const inline struct xsm_ops *flask_init(const void *policy_buffer,
                                               size_t policy_size)
{
    return NULL;
}
#endif

#ifdef CONFIG_XSM_FLASK_POLICY
extern const unsigned char xsm_flask_init_policy[];
extern const unsigned int xsm_flask_init_policy_size;
#endif

#ifdef CONFIG_XSM_SILO
extern const struct xsm_ops *silo_init(void);
#else
static const inline struct xsm_ops *silo_init(void)
{
    return NULL;
}
#endif

#else /* CONFIG_XSM */

#include <xsm/dummy.h>

#ifdef CONFIG_MULTIBOOT
struct boot_info;
static inline int xsm_multiboot_init(struct boot_info *bi)
{
    return 0;
}
#endif

#ifdef CONFIG_HAS_DEVICE_TREE_DISCOVERY
static inline int xsm_dt_init(void)
{
    return 0;
}

static inline bool has_xsm_magic(paddr_t start)
{
    return false;
}
#endif /* CONFIG_HAS_DEVICE_TREE_DISCOVERY */

#endif /* CONFIG_XSM */

#endif /* __XSM_H */
