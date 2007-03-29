/****************************************************************
 * secpol_xml2bin.c
 *
 * Copyright (C) 2005 IBM Corporation
 *
 * Author: Reiner Sailer <sailer@us.ibm.com>
 *
 * Maintained:
 * Reiner Sailer <sailer@us.ibm.com>
 * Ray Valdez <rvaldez@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype policy translation tool. This tool takes an XML
 * policy specification as input and produces a binary
 * policy file that can be loaded into Xen through the
 * ACM operations (xensec_tool loadpolicy) interface or at
 * boot time (grub module parameter)
 *
 * indent -i4 -kr -nut
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <libxml/xmlschemas.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>
#include <stdint.h>
#include <xen/acm.h>

#include "secpol_xml2bin.h"

#define DEBUG    0

#define NULL_LABEL_NAME "__NULL_LABEL__"

/* primary / secondary policy component setting */
enum policycomponent { CHWALL, STE, NULLPOLICY }
    primary = NULLPOLICY, secondary = NULLPOLICY;

/* general list element for ste and chwall type queues */
struct type_entry {
    TAILQ_ENTRY(type_entry) entries;
    char *name;                 /* name of type from xml file */
    type_t mapping;             /* type mapping into 16bit */
};

TAILQ_HEAD(tailhead, type_entry) ste_head, chwall_head;

/* general list element for all label queues */
enum label_type { VM, RES, ANY };
struct ssid_entry {
    TAILQ_ENTRY(ssid_entry) entries;
    char *name;                 /* label name */
    enum label_type type;       /* type: VM / RESOURCE LABEL */
    u_int32_t num;              /* ssid or referenced ssid */
    int is_ref;                 /* if this entry references earlier ssid number */
    unsigned char *row;         /* index of types (if not a reference) */
};

TAILQ_HEAD(tailhead_ssid, ssid_entry) ste_ssid_head, chwall_ssid_head,
    conflictsets_head;
struct ssid_entry *current_chwall_ssid_p = NULL;
struct ssid_entry *current_ste_ssid_p = NULL;
struct ssid_entry *current_conflictset_p = NULL;

/* which label to assign to dom0 during boot */
char *bootstrap_label;

u_int32_t max_ste_ssids = 0;
u_int32_t max_chwall_ssids = 0;
u_int32_t max_chwall_labels = 0;
u_int32_t max_ste_labels = 0;
u_int32_t max_conflictsets = 0;

char *current_ssid_name;        /* store name until structure is allocated */
char *current_conflictset_name; /* store name until structure is allocated */

/* dynamic list of type mappings for STE */
u_int32_t max_ste_types = 0;

/* dynamic list of type mappings for CHWALL */
u_int32_t max_chwall_types = 0;

/* dynamic list of conflict sets */
int max_conflict_set = 0;

/* which policies are defined */
int have_ste = 0;
int have_chwall = 0;

/* input/output file names */
char *policy_filename = NULL,
    *binary_filename = NULL,
    *mapping_filename = NULL, *schema_filename = NULL;

char *policy_reference_name = NULL;

char *policy_version_string = NULL;

void walk_labels(xmlNode * start, xmlDocPtr doc, unsigned long state);

void usage(char *prg)
{
    printf(
    "Usage: %s [OPTIONS] POLICYNAME\n"
    "POLICYNAME is the directory name within the policy directory\n"
    "that contains the policy files.  The default policy directory\n"
    "is '%s' (see the '-d' option below to change it)\n"
    "The policy files contained in the POLICYNAME directory must be named:\n"
    "\tPOLICYNAME-security_policy.xml\n"
    "\tPOLICYNAME-security_label_template.xml\n\n"
    "OPTIONS:\n"
    "\t-d POLICYDIR\n"
    "\t\tUse POLICYDIR as the policy directory. This directory must \n"
    "\t\tcontain the policy schema file 'security_policy.xsd'\n",
    prg, POLICY_DIR);
    exit(EXIT_FAILURE);
}


/***************** policy-related parsing *********************/

char *type_by_mapping(struct tailhead *head, u_int32_t mapping)
{
    struct type_entry *np;
    for (np = head->tqh_first; np != NULL; np = np->entries.tqe_next)
        if (np->mapping == mapping)
            return np->name;
    return NULL;
}


struct type_entry *lookup(struct tailhead *head, char *name)
{
    struct type_entry *np;
    for (np = head->tqh_first; np != NULL; np = np->entries.tqe_next)
        if (!(strcmp(np->name, name)))
            return np;
    return NULL;
}

/* enforces single-entry lists */
int add_entry(struct tailhead *head, char *name, type_t mapping)
{
    struct type_entry *e;
    if (lookup(head, name)) {
        printf("Error: Type >%s< defined more than once.\n", name);
        return -EFAULT;         /* already in the list */
    }
    if (!(e = malloc(sizeof(struct type_entry))))
        return -ENOMEM;

    e->name = name;
    e->mapping = mapping;
    TAILQ_INSERT_TAIL(head, e, entries);
    return 0;
}

int totoken(char *tok)
{
    int i;
    for (i = 0; token[i] != NULL; i++)
        if (!strcmp(token[i], tok))
            return i;
    return -EFAULT;
}

/* conflictsets use the same data structure as ssids; since
 * they are similar in structure (set of types)
 */
int init_next_conflictset(void)
{
    struct ssid_entry *conflictset = malloc(sizeof(struct ssid_entry));

    if (!conflictset)
        return -ENOMEM;

    conflictset->name = current_conflictset_name;
    conflictset->num = max_conflictsets++;
    conflictset->is_ref = 0;    /* n/a for conflictsets */
        /**
         *  row: allocate one byte per type;
         *  [i] != 0 --> mapped type >i< is part of the conflictset
         */
    conflictset->row = malloc(max_chwall_types);
    if (!conflictset->row)
        return -ENOMEM;

    memset(conflictset->row, 0, max_chwall_types);
    TAILQ_INSERT_TAIL(&conflictsets_head, conflictset, entries);
    current_conflictset_p = conflictset;
    return 0;
}

int register_type(xmlNode * cur_node, xmlDocPtr doc, unsigned long state)
{
    xmlChar *text;
    struct type_entry *e;


    text = xmlNodeListGetString(doc, cur_node->xmlChildrenNode, 1);
    if (!text) {
        printf("Error reading type name!\n");
        return -EFAULT;
    }

    switch (state) {
    case XML2BIN_stetype_S:
        if (add_entry(&ste_head, (char *) text, max_ste_types)) {
            xmlFree(text);
            return -EFAULT;
        }
        max_ste_types++;
        break;

    case XML2BIN_chwalltype_S:
        if (add_entry(&chwall_head, (char *) text, max_chwall_types)) {
            xmlFree(text);
            return -EFAULT;
        }
        max_chwall_types++;
        break;

    case XML2BIN_conflictsettype_S:
        /* a) search the type in the chwall_type list */
        e = lookup(&chwall_head, (char *) text);
        if (e == NULL) {
            printf("CS type >%s< not a CHWALL type.\n", text);
            xmlFree(text);
            return -EFAULT;
        }
        /* b) add type entry to the current cs set */
        if (current_conflictset_p->row[e->mapping]) {
            printf
                ("ERROR: Double entry of type >%s< in conflict set %d.\n",
                 text, current_conflictset_p->num);
            xmlFree(text);
            return -EFAULT;
        }
        current_conflictset_p->row[e->mapping] = 1;
        break;

    default:
        printf("Incorrect type environment (state = %lx, text = %s).\n",
               state, text);
        xmlFree(text);
        return -EFAULT;
    }
    return 0;
}

void set_component_type(xmlNode * cur_node, enum policycomponent pc)
{
    xmlChar *order;

    if ((order =
         xmlGetProp(cur_node, (xmlChar *) PRIMARY_COMPONENT_ATTR_NAME))) {
        if (strcmp((char *) order, PRIMARY_COMPONENT)) {
            printf("ERROR: Illegal attribut value >order=%s<.\n",
                   (char *) order);
            xmlFree(order);
            exit(EXIT_FAILURE);
        }
        if (primary != NULLPOLICY) {
            printf("ERROR: Primary Policy Component set twice!\n");
            exit(EXIT_FAILURE);
        }
        primary = pc;
        xmlFree(order);
    }
}

void walk_policy(xmlNode * start, xmlDocPtr doc, unsigned long state)
{
    xmlNode *cur_node = NULL;
    int code;

    for (cur_node = start; cur_node; cur_node = cur_node->next) {
        if ((code = totoken((char *) cur_node->name)) < 0) {
            printf("Unknown token: >%s<. Aborting.\n", cur_node->name);
            exit(EXIT_FAILURE);
        }
        switch (code) {         /* adjust state to new state */
        case XML2BIN_SECPOL:
        case XML2BIN_STETYPES:
        case XML2BIN_CHWALLTYPES:
        case XML2BIN_CONFLICTSETS:
        case XML2BIN_POLICYHEADER:
        case XML2BIN_FROMPOLICY:
            walk_policy(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_POLICYNAME:       /* get policy reference name .... */
            if (state != XML2BIN_PN_S &&
                state != XML2BIN_PN_frompolicy_S) {
                printf("ERROR: >Url< >%s< out of context.\n",
                       (char *) xmlNodeListGetString(doc,
                                                     cur_node->
                                                     xmlChildrenNode, 1));
                exit(EXIT_FAILURE);
            }
            if (state == XML2BIN_PN_S) {
                policy_reference_name = (char *)
                    xmlNodeListGetString(doc, cur_node->xmlChildrenNode, 1);
                if (!policy_reference_name) {
                    printf("ERROR: empty >policy reference name (Url)<!\n");
                    exit(EXIT_FAILURE);
                } else
                    printf("Policy Reference name (Url): %s\n",
                           policy_reference_name);
            }
            break;

        case XML2BIN_VERSION:         /* get policy version number .... */
            if (state != XML2BIN_PN_S &&
                state != XML2BIN_PN_frompolicy_S) {
                printf("ERROR: >Url< >%s< out of context.\n",
                       (char *) xmlNodeListGetString(doc,
                                                     cur_node->
                                                     xmlChildrenNode, 1));
                exit(EXIT_FAILURE);
            }
            if (state == XML2BIN_PN_S) {
                policy_version_string = (char *)
                    xmlNodeListGetString(doc, cur_node->xmlChildrenNode, 1);
                if (!policy_version_string) {
                    printf("ERROR: empty >policy version string <!\n");
                    exit(EXIT_FAILURE);
                } else
                    printf("Policy version string: %s\n",
                           policy_version_string);
            }
            break;

        case XML2BIN_STE:
            if (WRITTEN_AGAINST_ACM_STE_VERSION != ACM_STE_VERSION) {
                printf
                    ("ERROR: This program was written against another STE version.\n");
                exit(EXIT_FAILURE);
            }
            have_ste = 1;
            set_component_type(cur_node, STE);
            walk_policy(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_CHWALL:
            if (WRITTEN_AGAINST_ACM_CHWALL_VERSION != ACM_CHWALL_VERSION) {
                printf
                    ("ERROR: This program was written against another CHWALL version.\n");
                exit(EXIT_FAILURE);
            }
            have_chwall = 1;
            set_component_type(cur_node, CHWALL);
            walk_policy(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_CSTYPE:
            current_conflictset_name =
                (char *) xmlGetProp(cur_node, (xmlChar *) "name");
            if (!current_conflictset_name)
                current_conflictset_name = "";

            if (init_next_conflictset()) {
                printf
                    ("ERROR: creating new conflictset structure failed.\n");
                exit(EXIT_FAILURE);
            }
            walk_policy(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_TYPE:
            if (register_type(cur_node, doc, state))
                exit(EXIT_FAILURE);
            /* type leaf */
            break;

        case XML2BIN_LABELTEMPLATE:    /* handle in second pass */
        case XML2BIN_TEXT:
        case XML2BIN_COMMENT:
        case XML2BIN_DATE:
        case XML2BIN_REFERENCE:
        case XML2BIN_NSURL:    /* for future use: where to find global label / type name mappings */
        case XML2BIN_URL:      /* for future use: where to find policy */
            /* leaf - nothing to do */
            break;

        default:
            printf("Unkonwn token Error (%d) in Policy\n", code);
            exit(EXIT_FAILURE);
        }

    }
    return;
}

void init_type_mapping(void)
{
    printf("Creating ssid mappings ...\n");

    /* initialize the ste and chwall type lists */
    TAILQ_INIT(&ste_head);
    TAILQ_INIT(&chwall_head);
    TAILQ_INIT(&conflictsets_head);
}

void post_type_mapping(void)
{
    struct type_entry *te;
    struct ssid_entry *se;
    int i;

    /* determine primary/secondary policy component orders */
    if ((primary == NULLPOLICY) && have_chwall)
        primary = CHWALL;       /* default if not set */
    else if ((primary == NULLPOLICY) && have_ste)
        primary = STE;

    switch (primary) {

    case CHWALL:
        if (have_ste)
            secondary = STE;
        /* else default = NULLPOLICY */
        break;

    case STE:
        if (have_chwall)
            secondary = CHWALL;
        /* else default = NULLPOLICY */
        break;

    default:
        /* NULL/NULL policy */
        break;
    }

    if (!DEBUG)
        return;

    /* print queues */
    if (have_ste) {
        printf("STE-Type queue (%s):\n",
               (primary == STE) ? "PRIMARY" : "SECONDARY");
        for (te = ste_head.tqh_first; te != NULL;
             te = te->entries.tqe_next)
            printf("name=%22s, map=%x\n", te->name, te->mapping);
    }
    if (have_chwall) {
        printf("CHWALL-Type queue (%s):\n",
               (primary == CHWALL) ? "PRIMARY" : "SECONDARY");
        for (te = chwall_head.tqh_first; te != NULL;
             te = te->entries.tqe_next)
            printf("name=%s, map=%x\n", te->name, te->mapping);

        printf("Conflictset queue (max=%d):\n", max_conflictsets);
        for (se = conflictsets_head.tqh_first; se != NULL;
             se = se->entries.tqe_next) {
            printf("conflictset name >%s<\n",
                   se->name ? se->name : "NONAME");
            for (i = 0; i < max_chwall_types; i++)
                if (se->row[i])
                    printf("#%x ", i);
            printf("\n");
        }
    }
}


/***************** template-related parsing *********************/

/* add default ssid at head of ssid queues */
int init_ssid_queues(void)
{
    struct ssid_entry *default_ssid_chwall, *default_ssid_ste;

    default_ssid_chwall = malloc(sizeof(struct ssid_entry));
    default_ssid_ste = malloc(sizeof(struct ssid_entry));

    if ((!default_ssid_chwall) || (!default_ssid_ste))
        return -ENOMEM;

    /* default chwall ssid */
    default_ssid_chwall->name = NULL_LABEL_NAME;
    default_ssid_chwall->num = max_chwall_ssids++;
    default_ssid_chwall->is_ref = 0;
    default_ssid_chwall->type = ANY;

    default_ssid_chwall->row = malloc(max_chwall_types);

    if (!default_ssid_chwall->row)
        return -ENOMEM;

    memset(default_ssid_chwall->row, 0, max_chwall_types);

    TAILQ_INSERT_TAIL(&chwall_ssid_head, default_ssid_chwall, entries);
    current_chwall_ssid_p = default_ssid_chwall;
    max_chwall_labels++;

    /* default ste ssid */
    default_ssid_ste->name = NULL_LABEL_NAME;
    default_ssid_ste->num = max_ste_ssids++;
    default_ssid_ste->is_ref = 0;
    default_ssid_ste->type = ANY;

    default_ssid_ste->row = malloc(max_ste_types);

    if (!default_ssid_ste->row)
        return -ENOMEM;

    memset(default_ssid_ste->row, 0, max_ste_types);

    TAILQ_INSERT_TAIL(&ste_ssid_head, default_ssid_ste, entries);
    current_ste_ssid_p = default_ssid_ste;
    max_ste_labels++;
    return 0;
}

int init_next_chwall_ssid(unsigned long state)
{
    struct ssid_entry *ssid = malloc(sizeof(struct ssid_entry));

    if (!ssid)
        return -ENOMEM;

    ssid->name = current_ssid_name;
    ssid->num = max_chwall_ssids++;
    ssid->is_ref = 0;

    if (state & (1 << XML2BIN_VM))
        ssid->type = VM;
    else
        ssid->type = RES;
        /**
         *  row: allocate one byte per type;
         *  [i] != 0 --> mapped type >i< is part of the ssid
         */
    ssid->row = malloc(max_chwall_types);
    if (!ssid->row)
        return -ENOMEM;

    memset(ssid->row, 0, max_chwall_types);
    TAILQ_INSERT_TAIL(&chwall_ssid_head, ssid, entries);
    current_chwall_ssid_p = ssid;
    max_chwall_labels++;
    return 0;
}

int init_next_ste_ssid(unsigned long state)
{
    struct ssid_entry *ssid = malloc(sizeof(struct ssid_entry));

    if (!ssid)
        return -ENOMEM;

    ssid->name = current_ssid_name;
    ssid->num = max_ste_ssids++;
    ssid->is_ref = 0;

    if (state & (1 << XML2BIN_VM))
        ssid->type = VM;
    else
        ssid->type = RES;

        /**
         *  row: allocate one byte per type;
         *  [i] != 0 --> mapped type >i< is part of the ssid
         */
    ssid->row = malloc(max_ste_types);
    if (!ssid->row)
        return -ENOMEM;

    memset(ssid->row, 0, max_ste_types);
    TAILQ_INSERT_TAIL(&ste_ssid_head, ssid, entries);
    current_ste_ssid_p = ssid;
    max_ste_labels++;

    return 0;
}


/* adds a type to the current ssid */
int add_type(xmlNode * cur_node, xmlDocPtr doc, unsigned long state)
{
    xmlChar *text;
    struct type_entry *e;

    text = xmlNodeListGetString(doc, cur_node->xmlChildrenNode, 1);
    if (!text) {
        printf("Error reading type name!\n");
        return -EFAULT;
    }
    /* same for all: 1. lookup type mapping, 2. mark type in ssid */
    switch (state) {
    case XML2BIN_VM_STE_S:
    case XML2BIN_RES_STE_S:
        /* lookup the type mapping and include the type mapping into the array */
        if (!(e = lookup(&ste_head, (char *) text))) {
            printf("ERROR: unknown VM STE type >%s<.\n", text);
            exit(EXIT_FAILURE);
        }
        if (current_ste_ssid_p->row[e->mapping])
            printf("Warning: double entry of VM STE type >%s<.\n", text);

        current_ste_ssid_p->row[e->mapping] = 1;
        break;

    case XML2BIN_VM_CHWALL_S:
        /* lookup the type mapping and include the type mapping into the array */
        if (!(e = lookup(&chwall_head, (char *) text))) {
            printf("ERROR: unknown VM CHWALL type >%s<.\n", text);
            exit(EXIT_FAILURE);
        }
        if (current_chwall_ssid_p->row[e->mapping])
            printf("Warning: double entry of VM CHWALL type >%s<.\n",
                   text);

        current_chwall_ssid_p->row[e->mapping] = 1;
        break;

    default:
        printf("Incorrect type environment (state = %lx, text = %s).\n",
               state, text);
        xmlFree(text);
        return -EFAULT;
    }
    return 0;
}

void set_bootstrap_label(xmlNode * cur_node)
{
    xmlChar *order;

    if ((order =
         xmlGetProp(cur_node, (xmlChar *) BOOTSTRAP_LABEL_ATTR_NAME)))
        bootstrap_label = (char *) order;
    else {
        printf("ERROR: No bootstrap label defined!\n");
        exit(EXIT_FAILURE);
    }
}

void walk_labels(xmlNode * start, xmlDocPtr doc, unsigned long state)
{
    xmlNode *cur_node = NULL;
    int code;

    for (cur_node = start; cur_node; cur_node = cur_node->next) {
        if ((code = totoken((char *) cur_node->name)) < 0) {
            printf("Unkonwn token: >%s<. Aborting.\n", cur_node->name);
            exit(EXIT_FAILURE);
        }
        switch (code) {         /* adjust state to new state */
        case XML2BIN_SUBJECTS:
            set_bootstrap_label(cur_node);
            /* fall through */
        case XML2BIN_SECPOL:
        case XML2BIN_LABELTEMPLATE:
        case XML2BIN_VM:
        case XML2BIN_RES:
        case XML2BIN_OBJECTS:
            walk_labels(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_STETYPES:
            /* create new ssid entry to use and point current to it */
            if (init_next_ste_ssid(state)) {
                printf("ERROR: creating new ste ssid structure failed.\n");
                exit(EXIT_FAILURE);
            }
            walk_labels(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_CHWALLTYPES:
            /* create new ssid entry to use and point current to it */
            if (init_next_chwall_ssid(state)) {
                printf
                    ("ERROR: creating new chwall ssid structure failed.\n");
                exit(EXIT_FAILURE);
            }
            walk_labels(cur_node->children, doc, state | (1 << code));
            break;

        case XML2BIN_TYPE:
            /* add type to current ssid */
            if (add_type(cur_node, doc, state))
                exit(EXIT_FAILURE);
            break;

        case XML2BIN_NAME:
            if ((state == XML2BIN_VM_S) || (state == XML2BIN_RES_S)) {
                current_ssid_name = (char *)
                    xmlNodeListGetString(doc, cur_node->xmlChildrenNode,
                                         1);
                if (!current_ssid_name) {
                    printf("ERROR: empty >vm/res name<!\n");
                    exit(EXIT_FAILURE);
                }
            } else {
                printf
                    ("ERROR: >name< >%s< out of context (state = 0x%lx.\n",
                     (char *) xmlNodeListGetString(doc,
                                                   cur_node->
                                                   xmlChildrenNode, 1),
                     state);
                exit(EXIT_FAILURE);
            }
            break;

        case XML2BIN_TEXT:
        case XML2BIN_COMMENT:
        case XML2BIN_POLICYHEADER:
        case XML2BIN_STE:
        case XML2BIN_CHWALL:
            break;

        default:
            printf("Unkonwn token Error (%d) in Label Template\n", code);
            exit(EXIT_FAILURE);
        }
    }
    return;
}

/*
 * will go away as soon as we have non-static bootstrap ssidref for dom0
 */
void fixup_bootstrap_label(struct tailhead_ssid *head,
                           u_int32_t max_types, u_int32_t * max_ssids)
{
    struct ssid_entry *np;
    int i;

    /* should not happen if xml / xsd checks work */
    if (!bootstrap_label) {
        printf("ERROR: No bootstrap label defined.\n");
        exit(EXIT_FAILURE);
    }

    /* search bootstrap_label */
    for (np = head->tqh_first; np != NULL; np = np->entries.tqe_next) {
        if (!strcmp(np->name, bootstrap_label)) {
            break;
        }
    }

    if (!np) {
        /* bootstrap label not found */
        printf("ERROR: Bootstrap label >%s< not found.\n",
               bootstrap_label);
        exit(EXIT_FAILURE);
    }

    /* move this entry ahead in the list right after the default entry so it
     * receives ssidref 1/1 */
    TAILQ_REMOVE(head, np, entries);
    TAILQ_INSERT_AFTER(head, head->tqh_first, np, entries);

    /* renumber the ssids (we could also just switch places with 1st element) */
    for (np = head->tqh_first, i = 0; np != NULL;
         np = np->entries.tqe_next, i++)
        np->num = i;

}

void init_label_mapping(void)
{

    printf("Creating label mappings ...\n");
    /* initialize the ste and chwall type lists */
    TAILQ_INIT(&chwall_ssid_head);
    TAILQ_INIT(&ste_ssid_head);

    /* init with default ssids */
    if (init_ssid_queues()) {
        printf("ERROR adding default ssids.\n");
        exit(EXIT_FAILURE);
    }
}

void post_label_mapping(void)
{
    struct ssid_entry *np;
    int i;

    /*
     * now sort bootstrap label to the head of the list
     * (for now), dom0 assumes its label in the first
     * defined ssidref (1/1). 0/0 is the default non-Label
     */
    if (have_chwall)
        fixup_bootstrap_label(&chwall_ssid_head, max_chwall_types,
                              &max_chwall_ssids);
    if (have_ste)
        fixup_bootstrap_label(&ste_ssid_head, max_ste_types,
                              &max_ste_ssids);

    if (!DEBUG)
        return;

    /* print queues */
    if (have_chwall) {
        printf("CHWALL SSID queue (max ssidrefs=%d):\n", max_chwall_ssids);
        np = NULL;
        for (np = chwall_ssid_head.tqh_first; np != NULL;
             np = np->entries.tqe_next) {
            printf("SSID #%02u (Label=%s)\n", np->num, np->name);
            if (np->is_ref)
                printf("REFERENCE");
            else
                for (i = 0; i < max_chwall_types; i++)
                    if (np->row[i])
                        printf("#%02d ", i);
            printf("\n\n");
        }
    }
    if (have_ste) {
        printf("STE SSID queue (max ssidrefs=%d):\n", max_ste_ssids);
        np = NULL;
        for (np = ste_ssid_head.tqh_first; np != NULL;
             np = np->entries.tqe_next) {
            printf("SSID #%02u (Label=%s)\n", np->num, np->name);
            if (np->is_ref)
                printf("REFERENCE");
            else
                for (i = 0; i < max_ste_types; i++)
                    if (np->row[i])
                        printf("#%02d ", i);
            printf("\n\n");
        }
    }
}

void create_mappings(xmlDocPtr doc)
{
    xmlNode *doc_root_node = xmlDocGetRootElement(doc);

    /* walk the XML policy tree and fill in types and labels */
    init_type_mapping();
    walk_policy(doc_root_node, doc, XML2BIN_NULL);      /* first pass: types */
    post_type_mapping();
    init_label_mapping();
    walk_labels(doc_root_node, doc, XML2BIN_NULL);      /* second pass: labels */
    post_label_mapping();
}

/***************** writing the binary policy *********************/

/*
 * the mapping file is ascii-based since it will likely be used from
 * within scripts (using awk, grep, etc.);
 *
 * We print from high-level to low-level information so that with one
 * pass, any symbol can be resolved (e.g. Label -> types)
 */
int write_mapping(char *filename)
{

    struct ssid_entry *e;
    struct type_entry *t;
    int i;
    FILE *file;

    if ((file = fopen(filename, "w")) == NULL)
        return -EIO;

    fprintf(file, "POLICYREFERENCENAME    %s\n", policy_reference_name);
    fprintf(file, "MAGIC                  %08x\n", ACM_MAGIC);
    fprintf(file, "POLICY FILE            %s\n", policy_filename);
    fprintf(file, "BINARY FILE            %s\n", binary_filename);
    if (have_chwall) {
        fprintf(file, "MAX-CHWALL-TYPES       %08x\n", max_chwall_types);
        fprintf(file, "MAX-CHWALL-SSIDS       %08x\n", max_chwall_ssids);
        fprintf(file, "MAX-CHWALL-LABELS      %08x\n", max_chwall_labels);
    }
    if (have_ste) {
        fprintf(file, "MAX-STE-TYPES          %08x\n", max_ste_types);
        fprintf(file, "MAX-STE-SSIDS          %08x\n", max_ste_ssids);
        fprintf(file, "MAX-STE-LABELS         %08x\n", max_ste_labels);
    }
    fprintf(file, "\n");

    /* primary / secondary order for combined ssid synthesis/analysis
     * if no primary is named, then chwall is primary */
    switch (primary) {
    case CHWALL:
        fprintf(file, "PRIMARY                CHWALL\n");
        break;

    case STE:
        fprintf(file, "PRIMARY                STE\n");
        break;

    default:
        fprintf(file, "PRIMARY                NULL\n");
        break;
    }

    switch (secondary) {
    case CHWALL:
        fprintf(file, "SECONDARY              CHWALL\n");
        break;

    case STE:
        fprintf(file, "SECONDARY              STE\n");
        break;

    default:
        fprintf(file, "SECONDARY              NULL\n");
        break;
    }
    fprintf(file, "\n");

    /* first labels to ssid mappings */
    if (have_chwall) {
        for (e = chwall_ssid_head.tqh_first; e != NULL;
             e = e->entries.tqe_next) {
            fprintf(file, "LABEL->SSID %s CHWALL %-25s %8x\n",
                    (e->type ==
                     VM) ? "VM " : ((e->type == RES) ? "RES" : "ANY"),
                    e->name, e->num);
        }
        fprintf(file, "\n");
    }
    if (have_ste) {
        for (e = ste_ssid_head.tqh_first; e != NULL;
             e = e->entries.tqe_next) {
            fprintf(file, "LABEL->SSID %s STE    %-25s %8x\n",
                    (e->type ==
                     VM) ? "VM " : ((e->type == RES) ? "RES" : "ANY"),
                    e->name, e->num);
        }
        fprintf(file, "\n");
    }

    /* second ssid to type mappings */
    if (have_chwall) {
        for (e = chwall_ssid_head.tqh_first; e != NULL;
             e = e->entries.tqe_next) {
            if (e->is_ref)
                continue;

            fprintf(file, "SSID->TYPE CHWALL      %08x", e->num);

            for (i = 0; i < max_chwall_types; i++)
                if (e->row[i])
                    fprintf(file, " %s", type_by_mapping(&chwall_head, i));

            fprintf(file, "\n");
        }
        fprintf(file, "\n");
    }
    if (have_ste) {
        for (e = ste_ssid_head.tqh_first; e != NULL;
             e = e->entries.tqe_next) {
            if (e->is_ref)
                continue;

            fprintf(file, "SSID->TYPE STE         %08x", e->num);

            for (i = 0; i < max_ste_types; i++)
                if (e->row[i])
                    fprintf(file, " %s", type_by_mapping(&ste_head, i));

            fprintf(file, "\n");
        }
        fprintf(file, "\n");
    }
    /* third type mappings */
    if (have_chwall) {
        for (t = chwall_head.tqh_first; t != NULL; t = t->entries.tqe_next) {
            fprintf(file, "TYPE CHWALL            %-25s %8x\n",
                    t->name, t->mapping);
        }
        fprintf(file, "\n");
    }
    if (have_ste) {
        for (t = ste_head.tqh_first; t != NULL; t = t->entries.tqe_next) {
            fprintf(file, "TYPE STE               %-25s %8x\n",
                    t->name, t->mapping);
        }
        fprintf(file, "\n");
    }
    fclose(file);
    return 0;
}


unsigned char *write_policy_reference_binary(u_int32_t * len_pr)
{
    unsigned char *buf, *ptr;
    struct acm_policy_reference_buffer *pr_header;
    u_int32_t len;
    u_int32_t name_len;

    if (policy_reference_name == NULL) {
        printf("ERROR: No policy reference name found.\n");
        exit(EXIT_FAILURE);
    }
    name_len = strlen(policy_reference_name) + 1; /* strend '\0' */
    len = sizeof(struct acm_policy_reference_buffer) + name_len;
    len = (len + 7) & ~7; /* Alignment.  */
    buf = malloc(len);
    ptr = buf;

    if (!buf) {
        printf
            ("ERROR: out of memory allocating label reference buffer.\n");
        exit(EXIT_FAILURE);
    }
    memset (buf, 0, len);
    pr_header = (struct acm_policy_reference_buffer *) buf;
    pr_header->len = htonl(name_len);
    ptr += sizeof(struct acm_policy_reference_buffer);
    strcpy((char *) ptr, policy_reference_name);

    (*len_pr) = len;
    return buf;
}


unsigned char *write_chwall_binary(u_int32_t * len_chwall)
{
    unsigned char *buf, *ptr;
    struct acm_chwall_policy_buffer *chwall_header;
    u_int32_t len;
    struct ssid_entry *e;
    int i;

    if (!have_chwall)
        return NULL;

    len = sizeof(struct acm_chwall_policy_buffer) +
        sizeof(type_t) * max_chwall_types * max_chwall_ssids +
        sizeof(type_t) * max_chwall_types * max_conflictsets;

    buf = malloc(len);
    ptr = buf;

    if (!buf) {
        printf("ERROR: out of memory allocating chwall buffer.\n");
        exit(EXIT_FAILURE);
    }
    /* chwall has 3 parts : header, types, conflictsets */

    chwall_header = (struct acm_chwall_policy_buffer *) buf;
    chwall_header->chwall_max_types = htonl(max_chwall_types);
    chwall_header->chwall_max_ssidrefs = htonl(max_chwall_ssids);
    chwall_header->policy_code = htonl(ACM_CHINESE_WALL_POLICY);
    chwall_header->policy_version = htonl(ACM_CHWALL_VERSION);
    chwall_header->chwall_ssid_offset =
        htonl(sizeof(struct acm_chwall_policy_buffer));
    chwall_header->chwall_max_conflictsets = htonl(max_conflictsets);
    chwall_header->chwall_conflict_sets_offset =
        htonl(ntohl(chwall_header->chwall_ssid_offset) +
              sizeof(domaintype_t) * max_chwall_ssids * max_chwall_types);
    chwall_header->chwall_running_types_offset = 0;
    chwall_header->chwall_conflict_aggregate_offset = 0;
    ptr += sizeof(struct acm_chwall_policy_buffer);

    /* types */
    for (e = chwall_ssid_head.tqh_first; e != NULL;
         e = e->entries.tqe_next) {
        if (e->is_ref)
            continue;

        for (i = 0; i < max_chwall_types; i++)
            ((type_t *) ptr)[i] = htons((type_t) e->row[i]);

        ptr += sizeof(type_t) * max_chwall_types;
    }

    /* conflictsets */
    for (e = conflictsets_head.tqh_first; e != NULL;
         e = e->entries.tqe_next) {
        for (i = 0; i < max_chwall_types; i++)
            ((type_t *) ptr)[i] = htons((type_t) e->row[i]);

        ptr += sizeof(type_t) * max_chwall_types;
    }

    if ((ptr - buf) != len) {
        printf("ERROR: wrong lengths in %s.\n", __func__);
        exit(EXIT_FAILURE);
    }

    (*len_chwall) = len;
    return buf;
}

unsigned char *write_ste_binary(u_int32_t * len_ste)
{
    unsigned char *buf, *ptr;
    struct acm_ste_policy_buffer *ste_header;
    struct ssid_entry *e;
    u_int32_t len;
    int i;

    if (!have_ste)
        return NULL;

    len = sizeof(struct acm_ste_policy_buffer) +
        sizeof(type_t) * max_ste_types * max_ste_ssids;

    buf = malloc(len);
    ptr = buf;

    if (!buf) {
        printf("ERROR: out of memory allocating chwall buffer.\n");
        exit(EXIT_FAILURE);
    }

    /* fill buffer */
    ste_header = (struct acm_ste_policy_buffer *) buf;
    ste_header->policy_version = htonl(ACM_STE_VERSION);
    ste_header->policy_code = htonl(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY);
    ste_header->ste_max_types = htonl(max_ste_types);
    ste_header->ste_max_ssidrefs = htonl(max_ste_ssids);
    ste_header->ste_ssid_offset =
        htonl(sizeof(struct acm_ste_policy_buffer));

    ptr += sizeof(struct acm_ste_policy_buffer);

    /* types */
    for (e = ste_ssid_head.tqh_first; e != NULL; e = e->entries.tqe_next) {
        if (e->is_ref)
            continue;

        for (i = 0; i < max_ste_types; i++)
            ((type_t *) ptr)[i] = htons((type_t) e->row[i]);

        ptr += sizeof(type_t) * max_ste_types;
    }

    if ((ptr - buf) != len) {
        printf("ERROR: wrong lengths in %s.\n", __func__);
        exit(EXIT_FAILURE);
    }
    (*len_ste) = len;
    return buf;                 /* for now */
}

int write_binary(char *filename)
{
    struct acm_policy_buffer header;
    unsigned char *ste_buffer = NULL, *chwall_buffer =
        NULL, *policy_reference_buffer = NULL;
    u_int32_t len;
    int fd, ret = 0;
    uint32_t major = 0, minor = 0;

    u_int32_t len_ste = 0, len_chwall = 0, len_pr = 0;  /* length of policy components */

    if (policy_version_string)
        sscanf(policy_version_string,"%d.%d", &major, &minor);

    /* open binary file */
    if ((fd =
         open(filename, O_WRONLY | O_CREAT | O_TRUNC,
              S_IRUSR | S_IWUSR)) <= 0) {
        ret = -EIO;
        goto out1;
    }
    policy_reference_buffer = write_policy_reference_binary(&len_pr);
    ste_buffer = write_ste_binary(&len_ste);
    chwall_buffer = write_chwall_binary(&len_chwall);

    /* determine primary component (default chwall) */
    header.policy_version = htonl(ACM_POLICY_VERSION);
    header.magic = htonl(ACM_MAGIC);
    header.xml_pol_version.major = htonl(major);
    header.xml_pol_version.minor = htonl(minor);

    len = sizeof(struct acm_policy_buffer);
    if (have_chwall)
        len += len_chwall;
    if (have_ste)
        len += len_ste;
    len += len_pr;              /* policy reference is mandatory */
    header.len = htonl(len);

    header.policy_reference_offset =
        htonl(sizeof(struct acm_policy_buffer));

    header.primary_buffer_offset =
        htonl(sizeof(struct acm_policy_buffer) + len_pr);
    if (primary == CHWALL) {
        header.primary_policy_code = htonl(ACM_CHINESE_WALL_POLICY);
        header.secondary_buffer_offset =
            htonl((sizeof(struct acm_policy_buffer)) + len_pr +
                  len_chwall);
    } else if (primary == STE) {
        header.primary_policy_code =
            htonl(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY);
        header.secondary_buffer_offset =
            htonl((sizeof(struct acm_policy_buffer)) + len_pr +
                  len_ste);
    } else {
        /* null policy */
        header.primary_policy_code = htonl(ACM_NULL_POLICY);
        header.secondary_buffer_offset =
            htonl(header.primary_buffer_offset);
    }

    if (secondary == CHWALL)
        header.secondary_policy_code = htonl(ACM_CHINESE_WALL_POLICY);
    else if (secondary == STE)
        header.secondary_policy_code =
            htonl(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY);
    else
        header.secondary_policy_code = htonl(ACM_NULL_POLICY);

    if (write(fd, (void *) &header, sizeof(struct acm_policy_buffer))
        != sizeof(struct acm_policy_buffer)) {
        ret = -EIO;
        goto out1;
    }

    /* write label reference name */
    if (write(fd, policy_reference_buffer, len_pr) != len_pr) {
        ret = -EIO;
        goto out1;
    }
    /* write primary policy component */
    if (primary == CHWALL) {
        if (write(fd, chwall_buffer, len_chwall) != len_chwall) {
            ret = -EIO;
            goto out1;
        }
    } else if (primary == STE) {
        if (write(fd, ste_buffer, len_ste) != len_ste) {
            ret = -EIO;
            goto out1;
        }
    } else;                     /* NULL POLICY has no policy data */

    /* write secondary policy component */
    if (secondary == CHWALL) {
        if (write(fd, chwall_buffer, len_chwall) != len_chwall) {
            ret = -EIO;
            goto out1;
        }
    } else if (secondary == STE) {
        if (write(fd, ste_buffer, len_ste) != len_ste) {
            ret = -EIO;
            goto out1;
        }
    } else;                     /* NULL POLICY has no policy data */

  out1:
    /* cleanup */
    if (policy_reference_buffer)
        free(policy_reference_buffer);
    if (chwall_buffer)
        free(chwall_buffer);
    if (ste_buffer)
        free(ste_buffer);
    close(fd);
    return ret;
}

int is_valid(xmlDocPtr doc)
{
    int err = 0;
    xmlSchemaPtr schema_ctxt = NULL;
    xmlSchemaParserCtxtPtr schemaparser_ctxt = NULL;
    xmlSchemaValidCtxtPtr schemavalid_ctxt = NULL;

    schemaparser_ctxt = xmlSchemaNewParserCtxt(schema_filename);
    schema_ctxt = xmlSchemaParse(schemaparser_ctxt);
    schemavalid_ctxt = xmlSchemaNewValidCtxt(schema_ctxt);

#ifdef VALIDATE_SCHEMA
    /* only tested to be available from libxml2-2.6.20 upwards */
    if ((err = xmlSchemaIsValid(schemavalid_ctxt)) != 1) {
        printf("ERROR: Invalid schema file %s (err=%d)\n",
               schema_filename, err);
        err = -EIO;
        goto out;
    } else
        printf("XML Schema %s valid.\n", schema_filename);
#endif
    if ((err = xmlSchemaValidateDoc(schemavalid_ctxt, doc))) {
        err = -EIO;
        goto out;
    }
  out:
    xmlSchemaFreeValidCtxt(schemavalid_ctxt);
    xmlSchemaFreeParserCtxt(schemaparser_ctxt);
    xmlSchemaFree(schema_ctxt);
    return (err != 0) ? 0 : 1;
}

int main(int argc, char **argv)
{
    xmlDocPtr policydoc = NULL;

    int err = EXIT_FAILURE;

    char *file_prefix;
    int prefix_len;

    int opt_char;
    char *policy_dir = POLICY_DIR;

    if (ACM_POLICY_VERSION != WRITTEN_AGAINST_ACM_POLICY_VERSION) {
        printf
            ("ERROR: This program was written against an older ACM version.\n");
        printf("ERROR: ACM_POLICY_VERSION=%d, WRITTEN AGAINST= %d.\n",
               ACM_POLICY_VERSION, WRITTEN_AGAINST_ACM_POLICY_VERSION);
        exit(EXIT_FAILURE);
    }

    while ((opt_char = getopt(argc, argv, "d:")) != -1) {
        switch (opt_char) {
        case 'd':
            policy_dir = malloc(strlen(optarg) + 2);    /* null terminator and possibly "/" */
            if (!policy_dir) {
                printf("ERROR allocating directory name memory.\n");
                exit(EXIT_FAILURE);
            }
            strcpy(policy_dir, optarg);
            if (policy_dir[strlen(policy_dir) - 1] != '/')
                strcat(policy_dir, "/");
            break;

        default:
            usage(basename(argv[0]));
        }
    }

    if ((argc - optind) != 1)
        usage(basename(argv[0]));

    printf("arg=%s\n", argv[optind]);

    prefix_len =
        strlen(policy_dir) + strlen(argv[optind]) +
        1 /* null terminator */ ;

    file_prefix = malloc(prefix_len);
    policy_filename = malloc(prefix_len + strlen(POLICY_EXTENSION));
    binary_filename = malloc(prefix_len + strlen(BINARY_EXTENSION));
    mapping_filename = malloc(prefix_len + strlen(MAPPING_EXTENSION));
    schema_filename =
        malloc(strlen(policy_dir) + strlen(SCHEMA_FILENAME) + 1);

    if (!file_prefix || !policy_filename ||
        !binary_filename || !mapping_filename || !schema_filename) {
        printf("ERROR allocating file name memory.\n");
        goto out2;
    }

    /* create input/output filenames out of prefix */
    strcpy(file_prefix, policy_dir);
    strcat(file_prefix, argv[optind]);

    strcpy(policy_filename, file_prefix);
    strcpy(binary_filename, file_prefix);
    strcpy(mapping_filename, file_prefix);

    strcat(policy_filename, POLICY_EXTENSION);
    strcat(binary_filename, BINARY_EXTENSION);
    strcat(mapping_filename, MAPPING_EXTENSION);

    strcpy(schema_filename, policy_dir);
    strcat(schema_filename, SCHEMA_FILENAME);

    policydoc = xmlParseFile(policy_filename);

    if (policydoc == NULL) {
        printf("Error: could not parse file %s.\n", argv[optind]);
        goto out;
    }

    printf("Validating policy file %s...\n", policy_filename);

    if (!is_valid(policydoc)) {
        printf("ERROR: Failed schema-validation for file %s (err=%d)\n",
               policy_filename, err);
        goto out;
    }

    /* create mappings */
    create_mappings(policydoc);

    /* write label mapping file */
    if (write_mapping(mapping_filename)) {
        printf("ERROR: writing mapping file %s.\n", mapping_filename);
        goto out;
    }

    /* write binary file */
    if (write_binary(binary_filename)) {
        printf("ERROR: writing binary file %s.\n", binary_filename);
        goto out;
    }
    err = EXIT_SUCCESS;
    /* write stats */
    if (have_chwall) {
        printf("Max chwall labels:  %u\n", max_chwall_labels);
        printf("Max chwall-types:   %u\n", max_chwall_types);
        printf("Max chwall-ssids:   %u\n", max_chwall_ssids);
    }

    if (have_ste) {
        printf("Max ste labels:     %u\n", max_ste_labels);
        printf("Max ste-types:      %u\n", max_ste_types);
        printf("Max ste-ssids:      %u\n", max_ste_ssids);
    }
    /* cleanup */
  out:
    xmlFreeDoc(policydoc);
  out2:
    xmlCleanupParser();
    return err;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
