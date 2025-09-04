/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Generic ARM SCI (System Control Interface) subsystem.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (c) 2025 EPAM Systems
 */

#ifndef __ASM_ARM_SCI_H
#define __ASM_ARM_SCI_H

#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/types.h>

#ifdef CONFIG_ARM_SCI

struct sci_mediator_ops {
    /*
     * Called during domain construction. If it is requested to enable
     * SCI support, so SCI driver can create own structures for the new domain
     * and inform firmware about new domain (if required).
     * Mandatory.
     */
    int (*domain_init)(struct domain *d,
                       struct xen_domctl_createdomain *config);

    /*
     * Called during domain construction. The SCI driver uses
     * it to sanitize domain SCI configuration parameters.
     * Optional.
     */
    int (*domain_sanitise_config)(struct xen_domctl_createdomain *config);

    /*
     * Called during domain destruction, releases all resources, that
     * were allocated for domain.
     * Mandatory.
     */
    void (*domain_destroy)(struct domain *d);

    /*
     * Called during domain destruction to relinquish resources used
     * by SCI driver itself and request resources releasing from firmware.
     * Optional.
     */
    int (*relinquish_resources)(struct domain *d);

    /* SMC/HVC Handle callback */
    bool (*handle_call)(struct cpu_user_regs *regs);

    /*
     * Dom0 DT nodes handling callback so SCI driver can detect DT nodes it
     * need to handle and decide if those nodes need to be provided to Dom0.
     * Optional.
     */
    bool (*dom0_dt_handle_node)(struct domain *d, struct dt_device_node *node);

    /*
     * SCI driver callback called at the end of Dom0 DT generation, so
     * it can perform steps to modify DT to enable/disable SCI
     * functionality for Dom0.
     */
    int (*dom0_dt_finalize)(struct domain *d, void *fdt);

    /*
     * SCI driver callback called when DT device is passed through to guest,
     * so SCI driver can enable device access to the domain if SCI FW provides
     * Device specific access control functionality.
     * Optional.
     */
    int (*assign_dt_device)(struct domain *d, struct dt_phandle_args *ac_spec);
};


static inline bool sci_domain_is_enabled(struct domain *d)
{
    return d->arch.sci_enabled;
}

/*
 * Register SCI subsystem ops.
 *
 * Register SCI drivers operation and so enable SCI functionality.
 * Only one SCI driver is supported.
 */
int sci_register(const struct sci_mediator_ops *ops);

/*
 * Initialize SCI functionality for domain if configured.
 *
 * Initialization routine to enable SCI functionality for the domain.
 * The SCI configuration data and decision about enabling SCI functionality
 * for the domain is SCI driver specific.
 */
int sci_domain_init(struct domain *d, struct xen_domctl_createdomain *config);

/*
 * Sanitise domain configuration parameters.
 *
 */
int sci_domain_sanitise_config(struct xen_domctl_createdomain *config);

/*
 * Destroy SCI domain instance.
 */
void sci_domain_destroy(struct domain *d);

/*
 * Free resources assigned to the certain domain.
 */
int sci_relinquish_resources(struct domain *d);

/*
 * SMC/HVC Handle callback.
 *
 * SCI driver acts as SMC/HVC server for the registered domains and
 * does redirection of the domain calls to the SCI firmware,
 * such as ARM TF-A or similar.
 */
bool sci_handle_call(struct cpu_user_regs *regs);

/*
 * Dom0 DT nodes handling function.
 *
 * Allows SCI driver to detect DT nodes it need to handle and decide if
 * those nodes need to be provided to Dom0.
 */
bool sci_dt_handle_node(struct domain *d, struct dt_device_node *node);

/*
 * Dom0 DT generation finalize.
 *
 * Called at the end of Dom0 DT generation, so SCI driver can perform steps
 * to modify DT to enable/disable SCI functionality for Dom0.
 */
int sci_dt_finalize(struct domain *d, void *fdt);

/*
 * Assign DT device to domain.
 *
 * Called when DT device is passed through to guest, so SCI driver can enable
 * device access to the domain if SCI FW provides "Device specific access
 * control" functionality.
 */
int sci_assign_dt_device(struct domain *d, struct dt_device_node *dev);
#else

static inline bool sci_domain_is_enabled(struct domain *d)
{
    return false;
}

static inline int sci_domain_init(struct domain *d,
                                  struct xen_domctl_createdomain *config)
{
    return 0;
}

static inline int
sci_domain_sanitise_config(struct xen_domctl_createdomain *config)
{
    return 0;
}

static inline void sci_domain_destroy(struct domain *d)
{}

static inline int sci_relinquish_resources(struct domain *d)
{
    return 0;
}

static inline bool sci_handle_call(struct cpu_user_regs *regs)
{
    return false;
}

static inline bool sci_dt_handle_node(struct domain *d,
                                      struct dt_device_node *node)
{
    return false;
}

static inline int sci_dt_finalize(struct domain *d, void *fdt)
{
    return 0;
}

static inline int sci_assign_dt_device(struct domain *d,
                                       struct dt_device_node *dev)
{
    return 0;
}

#endif /* CONFIG_ARM_SCI */

#endif /* __ASM_ARM_SCI_H */
