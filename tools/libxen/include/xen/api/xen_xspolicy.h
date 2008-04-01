/*
 * Copyright (c) 2007, IBM Corp.
 * Copyright (c) 2007, XenSource Inc.
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

#ifndef XEN_XSPOLICY_H
#define XEN_XSPOLICY_H

#include "xen_common.h"
#include "xen_xspolicy_decl.h"
#include "xen_string_string_map.h"


/*
 * The XSPolicy and associated data structures.
 *
 */
typedef int64_t xs_type;
typedef int64_t xs_instantiationflags;

enum xs_type {
    XS_POLICY_ACM = (1 << 0),
};

enum xs_instantiationflags {
    XS_INST_NONE = 0,
    XS_INST_BOOT = (1 << 0),
    XS_INST_LOAD = (1 << 1),
};


/* Error codes returned by xend following XSPolicy operations */
#define XSERR_BASE                       0x1000

#define XSERR_SUCCESS                    0
#define XSERR_GENERAL_FAILURE            1 + XSERR_BASE
#define XSERR_BAD_XML                    2 + XSERR_BASE
#define XSERR_XML_PROCESSING             3 + XSERR_BASE
#define XSERR_POLICY_INCONSISTENT        4 + XSERR_BASE
#define XSERR_FILE_ERROR                 5 + XSERR_BASE
#define XSERR_BAD_RESOURCE_FORMAT        6 + XSERR_BASE
#define XSERR_BAD_LABEL_FORMAT           7 + XSERR_BASE
#define XSERR_RESOURCE_NOT_LABELED       8 + XSERR_BASE
#define XSERR_RESOURCE_ALREADY_LABELED   9 + XSERR_BASE
#define XSERR_WRONG_POLICY_TYPE         10 + XSERR_BASE
#define XSERR_BOOTPOLICY_INSTALLED      11 + XSERR_BASE
#define XSERR_NO_DEFAULT_BOOT_TITLE     12 + XSERR_BASE
#define XSERR_POLICY_LOAD_FAILED        13 + XSERR_BASE
#define XSERR_POLICY_LOADED             14 + XSERR_BASE
#define XSERR_POLICY_TYPE_UNSUPPORTED   15 + XSERR_BASE
#define XSERR_BAD_CONFLICTSET           20 + XSERR_BASE
#define XSERR_RESOURCE_IN_USE           21 + XSERR_BASE
#define XSERR_BAD_POLICY_NAME           22 + XSERR_BASE
#define XSERR_RESOURCE_ACCESS           23 + XSERR_BASE
#define XSERR_HV_OP_FAILED              24 + XSERR_BASE
#define XSERR_BOOTPOLICY_INSTALL_ERROR  25 + XSERR_BASE
#define XSERR_VM_NOT_AUTHORIZED         26 + XSERR_BASE
#define XSERR_VM_IN_CONFLICT            27 + XSERR_BASE


/**
 * Free the given xen_xspolicy.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_xspolicy_free(xen_xspolicy xspolicy);


typedef struct xen_xspolicy_set
{
    size_t size;
    xen_xspolicy *contents[];
} xen_xspolicy_set;

/**
 * Allocate a xen_xspolicy_set of the given size.
 */
extern xen_xspolicy_set *
xen_xspolicy_set_alloc(size_t size);

/**
 * Free the given xen_xspolicy_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_xspolicy_set_free(xen_xspolicy_set *set);


typedef struct xen_xspolicy_record
{
    xen_xspolicy handle;
    char *uuid;
    char *repr;
    xs_instantiationflags flags;
    xs_type type;
} xen_xspolicy_record;

/**
 * Allocate a xen_xspolicy_record.
 */
extern xen_xspolicy_record *
xen_xspolicy_record_alloc(void);

/**
 * Free the given xen_xspolicy_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_xspolicy_record_free(xen_xspolicy_record *record);


typedef struct xen_xspolicy_record_opt
{
    bool is_record;
    union
    {
        xen_xspolicy handle;
        xen_xspolicy_record *record;
    } u;
} xen_xspolicy_record_opt;

/**
 * Allocate a xen_xspolicy_record_opt.
 */
extern xen_xspolicy_record_opt *
xen_xspolicy_record_opt_alloc(void);

/**
 * Free the given xen_xspolicy_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_xspolicy_record_opt_free(xen_xspolicy_record_opt *record_opt);


typedef struct xen_xspolicy_record_set
{
    size_t size;
    xen_xspolicy_record *contents[];
} xen_xspolicy_record_set;

/**
 * Allocate a xen_xspolicy_record_set of the given size.
 */
extern xen_xspolicy_record_set *
xen_xspolicy_record_set_alloc(size_t size);

/**
 * Free the given xen_xspolicy_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_xspolicy_record_set_free(xen_xspolicy_record_set *set);

/**
 * Data structures and function declarations for an XS Policy's state
 * information.
 */
typedef struct xen_xs_policystate
{
    xen_xspolicy_record_opt *xs_ref;
    int64_t xserr;
    char *repr;
    xs_type type;
    xs_instantiationflags flags;
    char *version;
    char *errors;
} xen_xs_policystate;

extern void
xen_xs_policystate_free(xen_xs_policystate *state);


/**
 * Get the referenced policy's record.
 */
extern bool
xen_xspolicy_get_record(xen_session *session, xen_xspolicy_record **result,
                        xen_xspolicy xspolicy);

/**
 * Get the UUID field of the given policy.
 */
extern bool
xen_xspolicy_get_uuid(xen_session *session, char **result,
                      xen_xspolicy xspolicy);

/**
 * Get a policy given it's UUID
 */
extern bool
xen_xspolicy_get_by_uuid(xen_session *session, xen_xspolicy *result,
                         char *uuid);


/**
 * Get the types of policies supported by the system.
 */
extern bool
xen_xspolicy_get_xstype(xen_session *session, xs_type *result);


/**
 * Get information about the currently managed policy.
 * (The API allows only one policy to be on the system.)
 */
extern bool
xen_xspolicy_get_xspolicy(xen_session *session, xen_xs_policystate **result);

/**
 * Activate the referenced policy by loading it into the hypervisor.
 */
extern bool
xen_xspolicy_activate_xspolicy(xen_session *session, int64_t *result,
                               xen_xspolicy xspolicy,
                               xs_instantiationflags flags);


/**
 * Set the system's policy to the given information comprising
 * type of policy, the xml representation of the policy, some flags
 * on whether to load the policy immediately and whether to overwrite
 * an existing policy on the system.
 */
extern bool
xen_xspolicy_set_xspolicy(xen_session *session, xen_xs_policystate **result,
                          xs_type type, char *repr, int64_t flags,
                          bool overwrite);



/**
 * Attempt to reset the system's policy to the DEFAULT policy for the
 * respective policy type. This is done by updating the system and therefore
 * underlies the same restrictions of a policy update. This operation may
 * for example fail if other domains than Domain-0 are running and have
 * different labels than Domain-0.
 */
extern bool
xen_xspolicy_reset_xspolicy(xen_session *session, xen_xs_policystate **result,
                            xs_type type);


/**
 * Remove any policy from having the system booted with.
 */
extern bool
xen_xspolicy_rm_xsbootpolicy(xen_session *session);

/**
 * Retrieve all labeled resources.
 */
extern bool
xen_xspolicy_get_labeled_resources(xen_session *session,
                                   xen_string_string_map **resources);

/**
 * Label a resource such as for example a hard drive partition or file
 */
extern bool
xen_xspolicy_set_resource_label(xen_session *session,
                                char *resource, char *label,
                                char *oldlabel);

/**
 * Get the label of a resource.
 */
extern bool
xen_xspolicy_get_resource_label(xen_session *session, char **label,
                                char *resource);

/**
 * Check whether a VM with the given VM-label could run.
 */
extern bool
xen_xspolicy_can_run(xen_session *session, int64_t *result,
                     char *security_label);

#endif
