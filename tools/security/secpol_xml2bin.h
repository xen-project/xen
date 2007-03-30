/****************************************************************
 * secpol_xml2bin.h
 *
 * Copyright (C) 2005 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */
#define POLICY_DIR          			"/etc/xen/acm-security/policies/"
#define POLICY_EXTENSION    			"-security_policy.xml"
#define BINARY_EXTENSION    			".bin"
#define MAPPING_EXTENSION   			".map"
#define PRIMARY_COMPONENT_ATTR_NAME 	"order"
#define BOOTSTRAP_LABEL_ATTR_NAME   	"bootstrap"
#define PRIMARY_COMPONENT   			"PrimaryPolicyComponent"
#define SCHEMA_FILENAME     			"security_policy.xsd"

/* basic states (used as 1 << X) */
enum {
    XML2BIN_SECPOL = 0,   /* policy tokens */
    XML2BIN_STE,
    XML2BIN_CHWALL,
    XML2BIN_CONFLICTSETS,
    XML2BIN_CSTYPE,
    XML2BIN_POLICYHEADER,
    XML2BIN_NSURL,
    XML2BIN_POLICYNAME,
    XML2BIN_URL,
    XML2BIN_REFERENCE,
    XML2BIN_DATE,
    XML2BIN_VERSION,
    XML2BIN_FROMPOLICY,

    XML2BIN_LABELTEMPLATE,  /* label tokens */
    XML2BIN_SUBJECTS,
    XML2BIN_OBJECTS,
    XML2BIN_VM,
    XML2BIN_RES,
    XML2BIN_NAME,

    XML2BIN_STETYPES,
    XML2BIN_CHWALLTYPES,
    XML2BIN_TYPE,
    XML2BIN_TEXT,
    XML2BIN_COMMENT,
    ENDOFLIST_POS /* keep last ! */
};

/* type "data type" (currently 16bit) */
typedef u_int16_t type_t;

/* list of known elements and token equivalent  *
 * state constants and token positions must be  *
 * in sync for correct state recognition        */

char *token[32] =                       /* parser triggers */
{
    [XML2BIN_SECPOL]        = "SecurityPolicyDefinition", /* policy xml */
    [XML2BIN_STE]           = "SimpleTypeEnforcement",
    [XML2BIN_CHWALL]        = "ChineseWall",
    [XML2BIN_CONFLICTSETS]  = "ConflictSets",
    [XML2BIN_CSTYPE]        = "Conflict",
    [XML2BIN_POLICYHEADER]  = "PolicyHeader",
    [XML2BIN_NSURL]         = "NameSpaceUrl",
    [XML2BIN_POLICYNAME]    = "PolicyName",
    [XML2BIN_URL]           = "PolicyUrl",
    [XML2BIN_REFERENCE]     = "Reference",
    [XML2BIN_DATE]          = "Date",
    [XML2BIN_VERSION]       = "Version",
    [XML2BIN_FROMPOLICY]    = "FromPolicy",

    [XML2BIN_LABELTEMPLATE] = "SecurityLabelTemplate", /* label-template xml */
    [XML2BIN_SUBJECTS]      = "SubjectLabels",
    [XML2BIN_OBJECTS]       = "ObjectLabels",
    [XML2BIN_VM]            = "VirtualMachineLabel",
    [XML2BIN_RES]           = "ResourceLabel",
    [XML2BIN_NAME]          = "Name",

    [XML2BIN_STETYPES]      = "SimpleTypeEnforcementTypes", /* common tags */
    [XML2BIN_CHWALLTYPES]   = "ChineseWallTypes",
    [XML2BIN_TYPE]          = "Type",
    [XML2BIN_TEXT]          = "text",
    [XML2BIN_COMMENT]       = "comment",
    [ENDOFLIST_POS]         = NULL  /* End of LIST, adapt ENDOFLIST_POS
                                       when adding entries */
};

/* important combined states */
#define XML2BIN_NULL 		0

/* policy xml parsing states _S */

/* e.g., here we are in a <secpol,ste,stetypes> environment,  *
 * so when finding a type element, we know where to put it    */
#define XML2BIN_stetype_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_STE) | \
                 (1 << XML2BIN_STETYPES))

#define XML2BIN_chwalltype_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_CHWALL) | \
                 (1 << XML2BIN_CHWALLTYPES))

#define XML2BIN_conflictset_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_CHWALL) | \
                 (1 << XML2BIN_CONFLICTSETS))

#define XML2BIN_conflictsettype_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_CHWALL) | \
                 (1 << XML2BIN_CONFLICTSETS) | \
                 (1 << XML2BIN_CSTYPE))

#define XML2BIN_PN_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_POLICYHEADER))

#define XML2BIN_PN_frompolicy_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_POLICYHEADER) | \
                 (1 << XML2BIN_FROMPOLICY))

/* label xml states */
#define XML2BIN_VM_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_LABELTEMPLATE) |	\
                 (1 << XML2BIN_SUBJECTS) | \
                 (1 << XML2BIN_VM))

#define XML2BIN_RES_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_LABELTEMPLATE) |	\
                 (1 << XML2BIN_OBJECTS) | \
                 (1 << XML2BIN_RES))

#define XML2BIN_VM_STE_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_LABELTEMPLATE) |	\
                 (1 << XML2BIN_SUBJECTS) | \
                 (1 << XML2BIN_VM) | \
                 (1 << XML2BIN_STETYPES))

#define XML2BIN_VM_CHWALL_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_LABELTEMPLATE) | \
                 (1 << XML2BIN_SUBJECTS) | \
                 (1 << XML2BIN_VM) | \
                 (1 << XML2BIN_CHWALLTYPES))

#define XML2BIN_RES_STE_S ((1 << XML2BIN_SECPOL) | \
                 (1 << XML2BIN_LABELTEMPLATE) | \
                 (1 << XML2BIN_OBJECTS) | \
                 (1 << XML2BIN_RES) | \
                 (1 << XML2BIN_STETYPES))


/* check versions of headers against which the
 * xml2bin translation tool was written
 */

/* protects from unnoticed changes in struct acm_policy_buffer */
#define WRITTEN_AGAINST_ACM_POLICY_VERSION  3

/* protects from unnoticed changes in struct acm_chwall_policy_buffer */
#define WRITTEN_AGAINST_ACM_CHWALL_VERSION  1

/* protects from unnoticed changes in struct acm_ste_policy_buffer */
#define WRITTEN_AGAINST_ACM_STE_VERSION     1
