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
#define POLICY_DIR          "/etc/xen/acm-security/policies/"
#define POLICY_EXTENSION    "-security_policy.xml"
#define LABEL_EXTENSION     "-security_label_template.xml"
#define BINARY_EXTENSION    ".bin"
#define MAPPING_EXTENSION   ".map"
#define PRIMARY_COMPONENT_ATTR_NAME "order"
#define BOOTSTRAP_LABEL_ATTR_NAME   "bootstrap"
#define PRIMARY_COMPONENT   "PrimaryPolicyComponent"
#define SCHEMA_FILENAME     "security_policy.xsd"

/* basic states (used as 1 << X) */
#define XML2BIN_SECPOL		    0   /* policy tokens */
#define XML2BIN_STE		        1
#define XML2BIN_CHWALL          2
#define XML2BIN_CONFLICTSETS   	3
#define XML2BIN_CSTYPE	    	4

#define XML2BIN_SECTEMPLATE	    5   /* label tokens */
#define XML2BIN_POLICYHEADER   	6
#define XML2BIN_LABELHEADER     7
#define XML2BIN_SUBJECTS        8
#define XML2BIN_OBJECTS  	    9
#define XML2BIN_VM      	    10
#define XML2BIN_RES          	11

#define XML2BIN_STETYPES	    12  /* shared tokens */
#define XML2BIN_CHWALLTYPES	    13
#define XML2BIN_TYPE		    14
#define XML2BIN_NAME            15
#define XML2BIN_TEXT		    16
#define XML2BIN_COMMENT	    	17

/* type "data type" (currently 16bit) */
typedef u_int16_t type_t;

/* list of known elements and token equivalent  *
 * state constants and token positions must be  *
 * in sync for correct state recognition        */

char *token[20] =                       /* parser triggers */
{
    [0] = "SecurityPolicyDefinition",   /* policy xml */
    [1] = "SimpleTypeEnforcement",
    [2] = "ChineseWall",
    [3] = "ConflictSets",
    [4] = "Conflict",                   /* label-template xml */
    [5] = "SecurityLabelTemplate",
    [6] = "PolicyHeader",
    [7] = "LabelHeader",
    [8] = "SubjectLabels",
    [9] = "ObjectLabels",
    [10] = "VirtualMachineLabel",
    [11] = "ResourceLabel",
    [12] = "SimpleTypeEnforcementTypes",                  /* common tags */
    [13] = "ChineseWallTypes",
    [14] = "Type",
    [15] = "Name",
    [16] = "text",
    [17] = "comment",
    [18] = NULL,
};

/* important combined states */
#define XML2BIN_NULL 		0

/* policy xml parsing states _S */

/* e.g., here we are in a <secpol,ste,stetypes> environment,  *
 * so when finding a type element, we know where to put it    */
#define XML2BIN_stetype_S ((1 << XML2BIN_SECPOL) | \
				 (1 << XML2BIN_STE) | 	 \
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


/* label xml states */
#define XML2BIN_VM_S ((1 << XML2BIN_SECTEMPLATE) | \
                      (1 << XML2BIN_SUBJECTS) |    \
                      (1 << XML2BIN_VM))

#define XML2BIN_RES_S ((1 << XML2BIN_SECTEMPLATE) | \
                       (1 << XML2BIN_OBJECTS) |     \
                       (1 << XML2BIN_RES))

#define XML2BIN_VM_STE_S ((1 << XML2BIN_SECTEMPLATE) | \
                        (1 << XML2BIN_SUBJECTS) | \
                        (1 << XML2BIN_VM) | \
                        (1 << XML2BIN_STETYPES))

#define XML2BIN_VM_CHWALL_S ((1 << XML2BIN_SECTEMPLATE) | \
                           (1 << XML2BIN_SUBJECTS) | \
                           (1 << XML2BIN_VM) | \
                           (1 << XML2BIN_CHWALLTYPES))

#define XML2BIN_RES_STE_S ((1 << XML2BIN_SECTEMPLATE) | \
                         (1 << XML2BIN_OBJECTS) | \
                         (1 << XML2BIN_RES) | \
                         (1 << XML2BIN_STETYPES))



/* check versions of headers against which the
 * xml2bin translation tool was written
 */

/* protects from unnoticed changes in struct acm_policy_buffer */
#define WRITTEN_AGAINST_ACM_POLICY_VERSION  1

/* protects from unnoticed changes in struct acm_chwall_policy_buffer */
#define WRITTEN_AGAINST_ACM_CHWALL_VERSION  1

/* protects from unnoticed changes in struct acm_ste_policy_buffer */
#define WRITTEN_AGAINST_ACM_STE_VERSION     1
