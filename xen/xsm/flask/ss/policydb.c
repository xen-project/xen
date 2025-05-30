/*
 * Implementation of the policy database.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */

/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *    Support for enhanced MLS infrastructure.
 *
 * Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 *     Added conditional policy language extensions
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 *    This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, version 2.
 */

/* Ported to Xen 3.0, George Coker, <gscoker@alpha.ncsc.mil> */

#include <xen/byteorder.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/xmalloc.h>

#include <conditional.h>
#include "security.h"

#include "policydb.h"
#include "conditional.h"
#include "mls.h"

#define _DEBUG_HASHES

#ifdef DEBUG_HASHES
static char *symtab_name[SYM_NUM] = {
    "common prefixes",
    "classes",
    "roles",
    "types",
    "users",
    "bools",
    "levels",
    "categories",
};
#endif

int flask_mls_enabled = 0;

static unsigned int symtab_sizes[SYM_NUM] = {
    2,
    32,
    16,
    512,
    128,
    16,
    16,
    16,
};

struct policydb_compat_info {
    int version;
    int sym_num;
    int ocon_num;
    int target_type;
};

/* These need to be updated if SYM_NUM or OCON_NUM changes */
static struct policydb_compat_info policydb_compat[] = {
    {
        .version        = POLICYDB_VERSION_BASE,
        .sym_num        = SYM_NUM - 3,
        .ocon_num       = 4,
        .target_type    = TARGET_XEN_OLD,
    },
    {
        .version        = POLICYDB_VERSION_BOOL,
        .sym_num        = SYM_NUM - 2,
        .ocon_num       = 4,
        .target_type    = TARGET_XEN_OLD,
    },
    {
        .version        = POLICYDB_VERSION_IPV6,
        .sym_num        = SYM_NUM - 2,
        .ocon_num       = 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
        .version        = POLICYDB_VERSION_NLCLASS,
        .sym_num        = SYM_NUM - 2,
        .ocon_num       = 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
        .version        = POLICYDB_VERSION_MLS,
        .sym_num        = SYM_NUM,
        .ocon_num       = 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
        .version        = POLICYDB_VERSION_AVTAB,
        .sym_num        = SYM_NUM,
        .ocon_num       = 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
	.version	= POLICYDB_VERSION_RANGETRANS,
	.sym_num	= SYM_NUM,
	.ocon_num	= 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
	.version	= POLICYDB_VERSION_POLCAP,
	.sym_num	= SYM_NUM,
	.ocon_num	= 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
	.version	= POLICYDB_VERSION_PERMISSIVE,
	.sym_num	= SYM_NUM,
	.ocon_num	= 5,
        .target_type    = TARGET_XEN_OLD,
    },
    {
	.version	= POLICYDB_VERSION_BOUNDARY,
        .sym_num        = SYM_NUM,
        .ocon_num       = OCON_NUM_OLD,
        .target_type    = TARGET_XEN_OLD,
    },
    {
	.version	= POLICYDB_VERSION_BOUNDARY,
	.sym_num	= SYM_NUM,
	.ocon_num	= OCON_DEVICE + 1,
        .target_type    = TARGET_XEN,
    },
    {
	.version	= POLICYDB_VERSION_XEN_DEVICETREE,
	.sym_num	= SYM_NUM,
	.ocon_num	= OCON_DTREE + 1,
        .target_type    = TARGET_XEN,
    },
};

static struct policydb_compat_info *policydb_lookup_compat(int version,
                                                            int target)
{
    int i;
    struct policydb_compat_info *info = NULL;

    for ( i = 0; i < sizeof(policydb_compat)/sizeof(*info); i++ )
    {
        if ( policydb_compat[i].version == version &&
             policydb_compat[i].target_type == target )
        {
            info = &policydb_compat[i];
            break;
        }
    }
    return info;
}

/*
 * Initialize the role table.
 */
static int roles_init(struct policydb *p)
{
    char *key = NULL;
    int rc;
    struct role_datum *role;

    role = xzalloc(struct role_datum);
    if ( !role )
    {
        rc = -ENOMEM;
        goto out;
    }
    role->value = ++p->p_roles.nprim;
    if ( role->value != OBJECT_R_VAL )
    {
        rc = -EINVAL;
        goto out_free_role;
    }
    key = xmalloc_array(char, strlen(OBJECT_R)+1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto out_free_role;
    }
    strlcpy(key, OBJECT_R, strlen(OBJECT_R)+1);
    rc = hashtab_insert(p->p_roles.table, key, role);
    if ( rc )
        goto out_free_key;
out:
    return rc;

out_free_key:
    xfree(key);
out_free_role:
    xfree(role);
    goto out;
}

/*
 * Initialize a policy database structure.
 */
static int policydb_init(struct policydb *p)
{
    int i, rc;

    memset(p, 0, sizeof(*p));

    for ( i = 0; i < SYM_NUM; i++ )
    {
        rc = symtab_init(&p->symtab[i], symtab_sizes[i]);
        if ( rc )
            goto out_free_symtab;
    }

    rc = avtab_init(&p->te_avtab);
    if ( rc )
        goto out_free_symtab;

    rc = roles_init(p);
    if ( rc )
        goto out_free_avtab;

    rc = cond_policydb_init(p);
    if ( rc )
        goto out_free_avtab;

    ebitmap_init(&p->policycaps);
    ebitmap_init(&p->permissive_map);

out:
    return rc;

out_free_avtab:
    avtab_destroy(&p->te_avtab);

out_free_symtab:
    for ( i = 0; i < SYM_NUM; i++ )
        hashtab_destroy(p->symtab[i].table);
    goto out;
}

/*
 * The following *_index functions are used to
 * define the val_to_name and val_to_struct arrays
 * in a policy database structure.  The val_to_name
 * arrays are used when converting security context
 * structures into string representations.  The
 * val_to_struct arrays are used when the attributes
 * of a class, role, or user are needed.
 */

static int cf_check common_index(void *key, void *datum, void *datap)
{
    return 0;
}

static int cf_check class_index(void *key, void *datum, void *datap)
{
    struct policydb *p;
    struct class_datum *cladatum;

    cladatum = datum;
    p = datap;
    if ( !cladatum->value || cladatum->value > p->p_classes.nprim )
        return -EINVAL;
    p->p_class_val_to_name[cladatum->value - 1] = key;
    p->class_val_to_struct[cladatum->value - 1] = cladatum;
    return 0;
}

static int cf_check role_index(void *key, void *datum, void *datap)
{
    struct policydb *p;
    struct role_datum *role;

    role = datum;
    p = datap;
    if ( !role->value
         || role->value > p->p_roles.nprim
         || role->bounds > p->p_roles.nprim )
        return -EINVAL;
    p->p_role_val_to_name[role->value - 1] = key;
    p->role_val_to_struct[role->value - 1] = role;
    return 0;
}

static int cf_check type_index(void *key, void *datum, void *datap)
{
    struct policydb *p;
    struct type_datum *typdatum;

    typdatum = datum;
    p = datap;

    if ( typdatum->primary )
    {
        if ( !typdatum->value
             || typdatum->value > p->p_types.nprim
             || typdatum->bounds > p->p_types.nprim )
            return -EINVAL;
        p->p_type_val_to_name[typdatum->value - 1] = key;
        p->type_val_to_struct[typdatum->value - 1] = typdatum;
    }

    return 0;
}

static int cf_check user_index(void *key, void *datum, void *datap)
{
    struct policydb *p;
    struct user_datum *usrdatum;

    usrdatum = datum;
    p = datap;
    if ( !usrdatum->value
         || usrdatum->value > p->p_users.nprim
         || usrdatum->bounds > p->p_users.nprim )
        return -EINVAL;
    p->p_user_val_to_name[usrdatum->value - 1] = key;
    p->user_val_to_struct[usrdatum->value - 1] = usrdatum;
    return 0;
}

static int cf_check sens_index(void *key, void *datum, void *datap)
{
    struct policydb *p;
    struct level_datum *levdatum;

    levdatum = datum;
    p = datap;

    if ( !levdatum->isalias )
    {
        if ( !levdatum->level->sens || levdatum->level->sens >
                                                        p->p_levels.nprim )
            return -EINVAL;
        p->p_sens_val_to_name[levdatum->level->sens - 1] = key;
    }

    return 0;
}

static int cf_check cat_index(void *key, void *datum, void *datap)
{
    struct policydb *p;
    struct cat_datum *catdatum;

    catdatum = datum;
    p = datap;

    if ( !catdatum->isalias )
    {
        if ( !catdatum->value || catdatum->value > p->p_cats.nprim )
            return -EINVAL;
        p->p_cat_val_to_name[catdatum->value - 1] = key;
    }

    return 0;
}

static int (*index_f[SYM_NUM]) (void *key, void *datum, void *datap) =
{
    common_index,
    class_index,
    role_index,
    type_index,
    user_index,
    cond_index_bool,
    sens_index,
    cat_index,
};

/*
 * Define the class val_to_name and val_to_struct arrays in a policy
 * database structure.
 *
 * Caller must clean up upon failure.
 */
static int policydb_index_classes(struct policydb *p)
{
    int rc;

    p->class_val_to_struct =
        xmalloc_array(struct class_datum *, p->p_classes.nprim);
    if ( !p->class_val_to_struct )
    {
        rc = -ENOMEM;
        goto out;
    }

    p->p_class_val_to_name =
        xmalloc_array(char *, p->p_classes.nprim);
    if ( !p->p_class_val_to_name )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = hashtab_map(p->p_classes.table, class_index, p);
out:
    return rc;
}

#ifdef DEBUG_HASHES
static void symtab_hash_eval(struct symtab *s)
{
    int i;

    for ( i = 0; i < SYM_NUM; i++ )
    {
        struct hashtab *h = s[i].table;
        struct hashtab_info info;

        hashtab_stat(h, &info);
        printk(KERN_INFO "%s:  %d entries and %d/%d buckets used, "
               "longest chain length %d\n", symtab_name[i], h->nel,
               info.slots_used, h->size, info.max_chain_len);
    }
}
#endif

/*
 * Define the other val_to_name and val_to_struct arrays
 * in a policy database structure.
 *
 * Caller must clean up on failure.
 */
static int policydb_index_others(struct policydb *p)
{
    int i, rc = 0;

    printk(KERN_INFO "Flask:  %d users, %d roles, %d types, %d bools",
           p->p_users.nprim, p->p_roles.nprim, p->p_types.nprim, p->p_bools.nprim);
    if ( flask_mls_enabled )
        printk(", %d sens, %d cats", p->p_levels.nprim, p->p_cats.nprim);

    printk("\n");

    printk(KERN_INFO "Flask:  %d classes, %d rules\n",
           p->p_classes.nprim, p->te_avtab.nel);

#ifdef DEBUG_HASHES
    avtab_hash_eval(&p->te_avtab, "rules");
    symtab_hash_eval(p->symtab);
#endif

    p->role_val_to_struct =
        xmalloc_array(struct role_datum *, p->p_roles.nprim);
    if ( !p->role_val_to_struct )
    {
        rc = -ENOMEM;
        goto out;
    }

    p->user_val_to_struct =
        xmalloc_array(struct user_datum *, p->p_users.nprim);
    if ( !p->user_val_to_struct )
    {
        rc = -ENOMEM;
        goto out;
    }

    p->type_val_to_struct =
        xmalloc_array(struct type_datum *, p->p_types.nprim);
    if ( !p->type_val_to_struct )
    {
        rc = -ENOMEM;
        goto out;
    }

    if ( cond_init_bool_indexes(p) )
    {
        rc = -ENOMEM;
        goto out;
    }

    for ( i = SYM_ROLES; i < SYM_NUM; i++ )
    {
        p->sym_val_to_name[i] =
            xmalloc_array(char *, p->symtab[i].nprim);
        if ( !p->sym_val_to_name[i] )
        {
            rc = -ENOMEM;
            goto out;
        }
        rc = hashtab_map(p->symtab[i].table, index_f[i], p);
        if ( rc )
            goto out;
    }

out:
    return rc;
}

/*
 * The following *_destroy functions are used to
 * free any memory allocated for each kind of
 * symbol data in the policy database.
 */

static int cf_check perm_destroy(void *key, void *datum, void *p)
{
    xfree(key);
    xfree(datum);
    return 0;
}

static int cf_check common_destroy(void *key, void *datum, void *p)
{
    struct common_datum *comdatum;

    xfree(key);
    comdatum = datum;
    hashtab_map(comdatum->permissions.table, perm_destroy, NULL);
    hashtab_destroy(comdatum->permissions.table);
    xfree(datum);
    return 0;
}

static int cf_check class_destroy(void *key, void *datum, void *p)
{
    struct class_datum *cladatum;
    struct constraint_node *constraint, *ctemp;
    struct constraint_expr *e, *etmp;

    xfree(key);
    cladatum = datum;
    hashtab_map(cladatum->permissions.table, perm_destroy, NULL);
    hashtab_destroy(cladatum->permissions.table);
    constraint = cladatum->constraints;
    while ( constraint )
    {
        e = constraint->expr;
        while ( e )
        {
            ebitmap_destroy(&e->names);
            etmp = e;
            e = e->next;
            xfree(etmp);
        }
        ctemp = constraint;
        constraint = constraint->next;
        xfree(ctemp);
    }

    constraint = cladatum->validatetrans;
    while ( constraint )
    {
        e = constraint->expr;
        while ( e )
        {
            ebitmap_destroy(&e->names);
            etmp = e;
            e = e->next;
            xfree(etmp);
        }
        ctemp = constraint;
        constraint = constraint->next;
        xfree(ctemp);
    }

    xfree(cladatum->comkey);
    xfree(datum);
    return 0;
}

static int cf_check role_destroy(void *key, void *datum, void *p)
{
    struct role_datum *role;

    xfree(key);
    role = datum;
    ebitmap_destroy(&role->dominates);
    ebitmap_destroy(&role->types);
    xfree(datum);
    return 0;
}

static int cf_check type_destroy(void *key, void *datum, void *p)
{
    xfree(key);
    xfree(datum);
    return 0;
}

static int cf_check user_destroy(void *key, void *datum, void *p)
{
    struct user_datum *usrdatum;

    xfree(key);
    usrdatum = datum;
    ebitmap_destroy(&usrdatum->roles);
    ebitmap_destroy(&usrdatum->range.level[0].cat);
    ebitmap_destroy(&usrdatum->range.level[1].cat);
    ebitmap_destroy(&usrdatum->dfltlevel.cat);
    xfree(datum);
    return 0;
}

static int cf_check sens_destroy(void *key, void *datum, void *p)
{
    struct level_datum *levdatum;

    xfree(key);
    levdatum = datum;
    ebitmap_destroy(&levdatum->level->cat);
    xfree(levdatum->level);
    xfree(datum);
    return 0;
}

static int cf_check cat_destroy(void *key, void *datum, void *p)
{
    xfree(key);
    xfree(datum);
    return 0;
}

static int (*destroy_f[SYM_NUM]) (void *key, void *datum, void *datap) =
{
    common_destroy,
    class_destroy,
    role_destroy,
    type_destroy,
    user_destroy,
    cond_destroy_bool,
    sens_destroy,
    cat_destroy,
};

static void ocontext_destroy(struct ocontext *c, int i)
{
    context_destroy(&c->context);
    if ( i == OCON_ISID || i == OCON_DTREE )
        xfree(c->u.name);
    xfree(c);
}

/*
 * Free any memory allocated by a policy database structure.
 */
void policydb_destroy(struct policydb *p)
{
    struct ocontext *c, *ctmp;
    int i;
    struct role_allow *ra, *lra = NULL;
    struct role_trans *tr, *ltr = NULL;
    struct range_trans *rt, *lrt = NULL;

    for ( i = 0; i < SYM_NUM; i++ )
    {
        hashtab_map(p->symtab[i].table, destroy_f[i], NULL);
        hashtab_destroy(p->symtab[i].table);
    }

    for ( i = 0; i < SYM_NUM; i++ )
        xfree(p->sym_val_to_name[i]);

    xfree(p->class_val_to_struct);
    xfree(p->role_val_to_struct);
    xfree(p->user_val_to_struct);
    xfree(p->type_val_to_struct);

    avtab_destroy(&p->te_avtab);

    for ( i = 0; i < OCON_NUM; i++ )
    {
        c = p->ocontexts[i];
        while ( c )
        {
            ctmp = c;
            c = c->next;
            ocontext_destroy(ctmp,i);
        }
        p->ocontexts[i] = NULL;
    }

    cond_policydb_destroy(p);

    for ( tr = p->role_tr; tr; tr = tr->next )
    {
        xfree(ltr);
        ltr = tr;
    }
    xfree(ltr);

    for ( ra = p->role_allow; ra; ra = ra -> next )
    {
        xfree(lra);
        lra = ra;
    }
    xfree(lra);

    for ( rt = p->range_tr; rt; rt = rt -> next )
    {
        if ( lrt )
        {
            ebitmap_destroy(&lrt->target_range.level[0].cat);
            ebitmap_destroy(&lrt->target_range.level[1].cat);
            xfree(lrt);
        }
        lrt = rt;
    }
    if ( lrt )
    {
        ebitmap_destroy(&lrt->target_range.level[0].cat);
        ebitmap_destroy(&lrt->target_range.level[1].cat);
        xfree(lrt);
    }

    if ( p->type_attr_map )
        for ( i = 0; i < p->p_types.nprim; i++ )
            ebitmap_destroy(&p->type_attr_map[i]);
    xfree(p->type_attr_map);

    ebitmap_destroy(&p->policycaps);
    ebitmap_destroy(&p->permissive_map);

    return;
}

/*
 * Load the initial SIDs specified in a policy database
 * structure into a SID table.
 */
int policydb_load_isids(struct policydb *p, struct sidtab *s)
{
    struct ocontext *head, *c;
    int rc;

    rc = sidtab_init(s);
    if ( rc )
    {
        printk(KERN_ERR "Flask:  out of memory on SID table init\n");
        goto out;
    }

    head = p->ocontexts[OCON_ISID];
    for ( c = head; c; c = c->next )
    {
        if ( !c->context.user )
        {
            printk(KERN_ERR "Flask:  SID %s was never "
                   "defined.\n", c->u.name);
            rc = -EINVAL;
            goto out;
        }
        if ( sidtab_insert(s, c->sid, &c->context) )
        {
            printk(KERN_ERR "Flask:  unable to load initial "
                   "SID %s.\n", c->u.name);
            rc = -EINVAL;
            goto out;
        }
    }
out:
    return rc;
}

int policydb_class_isvalid(struct policydb *p, unsigned int class)
{
    if ( !class || class > p->p_classes.nprim )
        return 0;
    return 1;
}

int policydb_role_isvalid(struct policydb *p, unsigned int role)
{
    if ( !role || role > p->p_roles.nprim )
        return 0;
    return 1;
}

int policydb_type_isvalid(struct policydb *p, unsigned int type)
{
    if ( !type || type > p->p_types.nprim )
        return 0;
    return 1;
}

/*
 * Return 1 if the fields in the security context
 * structure `c' are valid.  Return 0 otherwise.
 */
int policydb_context_isvalid(struct policydb *p, struct context *c)
{
    struct role_datum *role;
    struct user_datum *usrdatum;

    if ( !c->role || c->role > p->p_roles.nprim )
        return 0;

    if ( !c->user || c->user > p->p_users.nprim )
        return 0;

    if ( !c->type || c->type > p->p_types.nprim )
        return 0;

    if ( c->role != OBJECT_R_VAL )
    {
        /*
         * Role must be authorized for the type.
         */
        role = p->role_val_to_struct[c->role - 1];
        if ( !ebitmap_get_bit(&role->types, c->type - 1) )
            /* role may not be associated with type */
            return 0;

        /*
         * User must be authorized for the role.
         */
        usrdatum = p->user_val_to_struct[c->user - 1];
        if ( !usrdatum )
            return 0;

        if ( !ebitmap_get_bit(&usrdatum->roles, c->role - 1) )
            /* user may not be associated with role */
            return 0;
    }

    if ( !mls_context_isvalid(p, c) )
        return 0;

    return 1;
}

/*
 * Read a MLS range structure from a policydb binary
 * representation file.
 */
static int mls_read_range_helper(struct mls_range *r, void *fp)
{
    __le32 buf[2];
    u32 items;
    int rc;

    rc = next_entry(buf, fp, sizeof(u32));
    if ( rc < 0 )
        goto out;

    items = le32_to_cpu(buf[0]);
    if ( items > ARRAY_SIZE(buf) )
    {
        printk(KERN_ERR "Flask: mls:  range overflow\n");
        rc = -EINVAL;
        goto out;
    }
    rc = next_entry(buf, fp, sizeof(u32) * items);
    if ( rc < 0 )
    {
        printk(KERN_ERR "Flask: mls:  truncated range\n");
        goto out;
    }
    r->level[0].sens = le32_to_cpu(buf[0]);
    if ( items > 1 )
        r->level[1].sens = le32_to_cpu(buf[1]);
    else
        r->level[1].sens = r->level[0].sens;

    rc = ebitmap_read(&r->level[0].cat, fp);
    if ( rc )
    {
        printk(KERN_ERR "Flask: mls:  error reading low "
               "categories\n");
        goto out;
    }
    if ( items > 1 )
    {
        rc = ebitmap_read(&r->level[1].cat, fp);
        if ( rc )
        {
            printk(KERN_ERR "Flask: mls:  error reading high "
                   "categories\n");
            goto bad_high;
        }
    }
    else
    {
        rc = ebitmap_cpy(&r->level[1].cat, &r->level[0].cat);
        if ( rc )
        {
            printk(KERN_ERR "Flask: mls:  out of memory\n");
            goto bad_high;
        }
    }

    rc = 0;
out:
    return rc;
bad_high:
    ebitmap_destroy(&r->level[0].cat);
    goto out;
}

/*
 * Read and validate a security context structure
 * from a policydb binary representation file.
 */
static int context_read_and_validate(struct context *c, struct policydb *p,
                                                                    void *fp)
{
    __le32 buf[3];
    int rc;

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
    {
        printk(KERN_ERR "Flask: context truncated\n");
        goto out;
    }
    c->user = le32_to_cpu(buf[0]);
    c->role = le32_to_cpu(buf[1]);
    c->type = le32_to_cpu(buf[2]);
    if ( p->policyvers >= POLICYDB_VERSION_MLS )
    {
        if ( mls_read_range_helper(&c->range, fp) )
        {
            printk(KERN_ERR "Flask: error reading MLS range of "
                   "context\n");
            rc = -EINVAL;
            goto out;
        }
    }

    if ( !policydb_context_isvalid(p, c) )
    {
        printk(KERN_ERR "Flask:  invalid security context\n");
        context_destroy(c);
        rc = -EINVAL;
    }
out:
    return rc;
}

/*
 * The following *_read functions are used to
 * read the symbol data from a policy database
 * binary representation file.
 */

static int perm_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct perm_datum *perdatum;
    int rc;
    __le32 buf[2];
    u32 len;

    perdatum = xzalloc(struct perm_datum);
    if ( !perdatum )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    perdatum->value = le32_to_cpu(buf[1]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    rc = hashtab_insert(h, key, perdatum);
    if ( rc )
        goto bad;
out:
    return rc;
bad:
    perm_destroy(key, perdatum, NULL);
    goto out;
}

static int cf_check common_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct common_datum *comdatum;
    __le32 buf[4];
    u32 len, nel;
    int i, rc;

    comdatum = xzalloc(struct common_datum);
    if ( !comdatum )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    comdatum->value = le32_to_cpu(buf[1]);

    rc = symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE);
    if ( rc )
        goto bad;
    comdatum->permissions.nprim = le32_to_cpu(buf[2]);
    nel = le32_to_cpu(buf[3]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    for ( i = 0; i < nel; i++ )
    {
        rc = perm_read(p, comdatum->permissions.table, fp);
        if ( rc )
            goto bad;
    }

    rc = hashtab_insert(h, key, comdatum);
    if ( rc )
        goto bad;
out:
    return rc;
bad:
    common_destroy(key, comdatum, NULL);
    goto out;
}

static int read_cons_helper(struct policydb *p, struct constraint_node **nodep,
                            int ncons, int allowxtarget, void *fp)
{
    struct constraint_node *c, *lc;
    struct constraint_expr *e, *le;
    __le32 buf[3];
    u32 nexpr;
    int rc, i, j, depth;

    lc = NULL;
    for ( i = 0; i < ncons; i++ )
    {
        c = xzalloc(struct constraint_node);
        if ( !c )
            return -ENOMEM;

        if ( lc )
        {
            lc->next = c;
        }
        else
        {
            *nodep = c;
        }

        rc = next_entry(buf, fp, (sizeof(u32) * 2));
        if ( rc < 0 )
            return rc;
        c->permissions = le32_to_cpu(buf[0]);
        nexpr = le32_to_cpu(buf[1]);
        le = NULL;
        depth = -1;
        for ( j = 0; j < nexpr; j++ )
        {
            e = xzalloc(struct constraint_expr);
            if ( !e )
                return -ENOMEM;

            if ( le )
                le->next = e;
            else
                c->expr = e;

            rc = next_entry(buf, fp, (sizeof(u32) * 3));
            if ( rc < 0 )
                return rc;
            e->expr_type = le32_to_cpu(buf[0]);
            e->attr = le32_to_cpu(buf[1]);
            e->op = le32_to_cpu(buf[2]);

            switch ( e->expr_type )
            {
                case CEXPR_NOT:
                    if ( depth < 0 )
                        return -EINVAL;
                break;
                case CEXPR_AND:
                case CEXPR_OR:
                    if ( depth < 1 )
                        return -EINVAL;
                    depth--;
                break;
                case CEXPR_ATTR:
                    if ( depth == (CEXPR_MAXDEPTH - 1) )
                        return -EINVAL;
                    depth++;
                break;
                case CEXPR_NAMES:
                    if ( !allowxtarget && (e->attr & CEXPR_XTARGET) )
                        return -EINVAL;
                    if ( depth == (CEXPR_MAXDEPTH - 1) )
                        return -EINVAL;
                    depth++;
                    if ( ebitmap_read(&e->names, fp) )
                        return -EINVAL;
                    if ( p->policyvers >= POLICYDB_VERSION_CONSTRAINT_NAMES )
                    {
                        struct ebitmap dummy;
                        ebitmap_init(&dummy);
                        if ( ebitmap_read(&dummy, fp) )
                            return -EINVAL;
                        ebitmap_destroy(&dummy);

                        ebitmap_init(&dummy);
                        if ( ebitmap_read(&dummy, fp) )
                            return -EINVAL;
                        ebitmap_destroy(&dummy);

                        rc = next_entry(buf, fp, sizeof(u32));
                        if ( rc < 0 )
                            return rc;
                    }
                break;
                default:
                    return -EINVAL;
            }
            le = e;
        }
        if ( depth != 0 )
            return -EINVAL;
        lc = c;
    }

    return 0;
}

static int cf_check class_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct class_datum *cladatum;
    __le32 buf[6];
    u32 len, len2, ncons, nel;
    int i, rc;

    cladatum = xzalloc(struct class_datum);
    if ( !cladatum )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = next_entry(buf, fp, sizeof(u32)*6);
    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    len2 = le32_to_cpu(buf[1]);
    cladatum->value = le32_to_cpu(buf[2]);

    rc = symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE);
    if ( rc )
        goto bad;
    cladatum->permissions.nprim = le32_to_cpu(buf[3]);
    nel = le32_to_cpu(buf[4]);

    ncons = le32_to_cpu(buf[5]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    if ( len2 )
    {
        printk(KERN_ERR "Flask:  classes with common prefixes are not supported\n");
        rc = -EINVAL;
        goto bad;
    }
    for ( i = 0; i < nel; i++ )
    {
        rc = perm_read(p, cladatum->permissions.table, fp);
        if ( rc )
            goto bad;
    }

    rc = read_cons_helper(p, &cladatum->constraints, ncons, 0, fp);
    if ( rc )
        goto bad;

    if ( p->policyvers >= POLICYDB_VERSION_VALIDATETRANS )
    {
        /* grab the validatetrans rules */
        rc = next_entry(buf, fp, sizeof(u32));
        if ( rc < 0 )
            goto bad;
        ncons = le32_to_cpu(buf[0]);
        rc = read_cons_helper(p, &cladatum->validatetrans, ncons, 1, fp);
        if ( rc )
            goto bad;
    }

    if ( p->policyvers >= POLICYDB_VERSION_NEW_OBJECT_DEFAULTS )
    {
        rc = next_entry(buf, fp, sizeof(u32) * 3);
        if ( rc )
            goto bad;
        /* these values are ignored by Xen */
    }

    if ( p->policyvers >= POLICYDB_VERSION_DEFAULT_TYPE )
    {
        rc = next_entry(buf, fp, sizeof(u32) * 1);
        if ( rc )
            goto bad;
        /* ignored by Xen */
    }

    rc = hashtab_insert(h, key, cladatum);
    if ( rc )
        goto bad;

    rc = 0;
out:
    return rc;
bad:
    class_destroy(key, cladatum, NULL);
    goto out;
}

static int cf_check role_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct role_datum *role;
    int rc;
    __le32 buf[3];
    u32 len;
    u32 ver = p->policyvers;

    role = xzalloc(struct role_datum);
    if ( !role )
    {
        rc = -ENOMEM;
        goto out;
    }

    if ( ver >= POLICYDB_VERSION_BOUNDARY )
        rc = next_entry(buf, fp, sizeof(buf[0]) * 3);
    else
        rc = next_entry(buf, fp, sizeof(buf[0]) * 2);

    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    role->value = le32_to_cpu(buf[1]);
    if ( ver >= POLICYDB_VERSION_BOUNDARY )
        role->bounds = le32_to_cpu(buf[2]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    rc = ebitmap_read(&role->dominates, fp);
    if ( rc )
        goto bad;

    rc = ebitmap_read(&role->types, fp);
    if ( rc )
        goto bad;

    if ( strcmp(key, OBJECT_R) == 0 )
    {
        if ( role->value != OBJECT_R_VAL )
        {
            printk(KERN_ERR "Role %s has wrong value %d\n", OBJECT_R,
                                                                role->value);
            rc = -EINVAL;
            goto bad;
        }
        rc = 0;
        goto bad;
    }

    rc = hashtab_insert(h, key, role);
    if ( rc )
        goto bad;
out:
    return rc;
bad:
    role_destroy(key, role, NULL);
    goto out;
}

static int cf_check type_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct type_datum *typdatum;
    int rc;
    __le32 buf[4];
    u32 len;
    u32 ver = p->policyvers;

    typdatum = xzalloc(struct type_datum);
    if ( !typdatum )
    {
        rc = -ENOMEM;
        return rc;
    }

    if ( ver >= POLICYDB_VERSION_BOUNDARY )
        rc = next_entry(buf, fp, sizeof(buf[0]) * 4);
    else
        rc = next_entry(buf, fp, sizeof(buf[0]) * 3);

    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    typdatum->value = le32_to_cpu(buf[1]);
    if ( ver >= POLICYDB_VERSION_BOUNDARY )
    {
        u32 prop = le32_to_cpu(buf[2]);

        if ( prop & TYPEDATUM_PROPERTY_PRIMARY )
            typdatum->primary = 1;
        if ( prop & TYPEDATUM_PROPERTY_ATTRIBUTE )
            typdatum->attribute = 1;

        typdatum->bounds = le32_to_cpu(buf[3]);
    }
    else
    {
        typdatum->primary = le32_to_cpu(buf[2]);
    }

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    rc = hashtab_insert(h, key, typdatum);
    if ( rc )
        goto bad;
out:
    return rc;
bad:
    type_destroy(key, typdatum, NULL);
    goto out;
}


/*
 * Read a MLS level structure from a policydb binary
 * representation file.
 */
static int mls_read_level(struct mls_level *lp, void *fp)
{
    __le32 buf[1];
    int rc;

    memset(lp, 0, sizeof(*lp));

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
    {
        printk(KERN_ERR "Flask: mls: truncated level\n");
        goto bad;
    }
    lp->sens = le32_to_cpu(buf[0]);

    if ( ebitmap_read(&lp->cat, fp) )
    {
        printk(KERN_ERR "Flask: mls:  error reading level categories\n");
        goto bad;
    }
    return 0;

bad:
    return -EINVAL;
}

static int cf_check user_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct user_datum *usrdatum;
    int rc;
    __le32 buf[3];
    u32 len;
    u32 ver = p->policyvers;

    usrdatum = xzalloc(struct user_datum);
    if ( !usrdatum )
    {
        rc = -ENOMEM;
        goto out;
    }

    if ( ver >= POLICYDB_VERSION_BOUNDARY )
        rc = next_entry(buf, fp, sizeof(buf[0]) * 3);
    else
        rc = next_entry(buf, fp, sizeof(buf[0]) * 2);

    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    usrdatum->value = le32_to_cpu(buf[1]);
    if ( ver >= POLICYDB_VERSION_BOUNDARY )
        usrdatum->bounds = le32_to_cpu(buf[2]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    rc = ebitmap_read(&usrdatum->roles, fp);
    if ( rc )
        goto bad;

    if ( ver >= POLICYDB_VERSION_MLS )
    {
        rc = mls_read_range_helper(&usrdatum->range, fp);
        if ( rc )
            goto bad;
        rc = mls_read_level(&usrdatum->dfltlevel, fp);
        if ( rc )
            goto bad;
    }

    rc = hashtab_insert(h, key, usrdatum);
    if ( rc )
        goto bad;
out:
    return rc;
bad:
    user_destroy(key, usrdatum, NULL);
    goto out;
}

static int cf_check sens_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct level_datum *levdatum;
    int rc;
    __le32 buf[2];
    u32 len;

    levdatum = xzalloc(struct level_datum);
    if ( !levdatum )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    levdatum->isalias = le32_to_cpu(buf[1]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    levdatum->level = xmalloc(struct mls_level);
    if ( !levdatum->level )
    {
        rc = -ENOMEM;
        goto bad;
    }
    if ( mls_read_level(levdatum->level, fp) )
    {
        rc = -EINVAL;
        goto bad;
    }

    rc = hashtab_insert(h, key, levdatum);
    if ( rc )
        goto bad;
out:
    return rc;
bad:
    sens_destroy(key, levdatum, NULL);
    goto out;
}

static int cf_check cat_read(struct policydb *p, struct hashtab *h, void *fp)
{
    char *key = NULL;
    struct cat_datum *catdatum;
    int rc;
    __le32 buf[3];
    u32 len;

    catdatum = xzalloc(struct cat_datum);
    if ( !catdatum )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
        goto bad;

    len = le32_to_cpu(buf[0]);
    catdatum->value = le32_to_cpu(buf[1]);
    catdatum->isalias = le32_to_cpu(buf[2]);

    key = xmalloc_array(char, len + 1);
    if ( !key )
    {
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(key, fp, len);
    if ( rc < 0 )
        goto bad;
    key[len] = 0;

    rc = hashtab_insert(h, key, catdatum);
    if ( rc )
        goto bad;
out:
    return rc;

bad:
    cat_destroy(key, catdatum, NULL);
    goto out;
}

static int (*read_f[SYM_NUM]) (struct policydb *p, struct hashtab *h, void *fp) =
{
    common_read,
    class_read,
    role_read,
    type_read,
    user_read,
    cond_read_bool,
    sens_read,
    cat_read,
};

static int cf_check user_bounds_sanity_check(
    void *key, void *datum, void *datap)
{
    struct user_datum *upper, *user;
    struct policydb *p = datap;
    int depth = 0;

    upper = user = datum;
    while (upper->bounds)
    {
        struct ebitmap_node *node;
        unsigned long bit;

        if ( ++depth == POLICYDB_BOUNDS_MAXDEPTH )
        {
            printk(KERN_ERR "Flask: user %s: "
                   "too deep or looped boundary",
                   (char *) key);
            return -EINVAL;
        }

        upper = p->user_val_to_struct[upper->bounds - 1];
        ebitmap_for_each_positive_bit(&user->roles, node, bit)
        {
            if ( ebitmap_get_bit(&upper->roles, bit) )
                continue;

            printk(KERN_ERR
                   "Flask: boundary violated policy: "
                   "user=%s role=%s bounds=%s\n",
                   p->p_user_val_to_name[user->value - 1],
                   p->p_role_val_to_name[bit],
                   p->p_user_val_to_name[upper->value - 1]);

            return -EINVAL;
        }
    }

    return 0;
}

static int cf_check role_bounds_sanity_check(
    void *key, void *datum, void *datap)
{
    struct role_datum *upper, *role;
    struct policydb *p = datap;
    int depth = 0;

    upper = role = datum;
    while (upper->bounds)
    {
        struct ebitmap_node *node;
        unsigned long bit;

        if ( ++depth == POLICYDB_BOUNDS_MAXDEPTH )
        {
            printk(KERN_ERR "Flask: role %s: "
                   "too deep or looped bounds\n",
                   (char *) key);
            return -EINVAL;
        }

        upper = p->role_val_to_struct[upper->bounds - 1];
        ebitmap_for_each_positive_bit(&role->types, node, bit)
        {
            if ( ebitmap_get_bit(&upper->types, bit) )
                continue;

            printk(KERN_ERR
                   "Flask: boundary violated policy: "
                   "role=%s type=%s bounds=%s\n",
                   p->p_role_val_to_name[role->value - 1],
                   p->p_type_val_to_name[bit],
                   p->p_role_val_to_name[upper->value - 1]);

            return -EINVAL;
        }
    }

    return 0;
}

static int cf_check type_bounds_sanity_check(
    void *key, void *datum, void *datap)
{
    struct type_datum *upper, *type;
    struct policydb *p = datap;
    int depth = 0;

    upper = type = datum;
    while (upper->bounds)
    {
        if ( ++depth == POLICYDB_BOUNDS_MAXDEPTH )
        {
            printk(KERN_ERR "Flask: type %s: "
			       "too deep or looped boundary\n",
			       (char *) key);
            return -EINVAL;
        }

        upper = p->type_val_to_struct[upper->bounds - 1];
        if ( upper->attribute )
        {
            printk(KERN_ERR "Flask: type %s: "
			       "bounded by attribute %s",
			       (char *) key,
			       p->p_type_val_to_name[upper->value - 1]);
            return -EINVAL;
        }
    }

    return 0;
}

static int policydb_bounds_sanity_check(struct policydb *p)
{
    int rc;

    if ( p->policyvers < POLICYDB_VERSION_BOUNDARY )
        return 0;

    rc = hashtab_map(p->p_users.table,
                     user_bounds_sanity_check, p);
    if ( rc )
        return rc;

    rc = hashtab_map(p->p_roles.table,
                     role_bounds_sanity_check, p);
    if ( rc )
        return rc;

    rc = hashtab_map(p->p_types.table,
                     type_bounds_sanity_check, p);
    if ( rc )
        return rc;

    return 0;
}

/*
 * Read the configuration data from a policy database binary
 * representation file into a policy database structure.
 */
int policydb_read(struct policydb *p, void *fp)
{
    struct role_allow *ra, *lra;
    struct role_trans *tr, *ltr;
    struct ocontext *l, *c, **pn;
    int i, j, rc;
    __le32 buf[8];
    u32 len, /*len2,*/ config, nprim, nel /*, nel2*/;
    char *policydb_str;
    struct policydb_compat_info *info;
    struct range_trans *rt, *lrt;

    config = 0;
    rc = policydb_init(p);
    if ( rc )
        goto out;

    /* Read the magic number and string length. */
    rc = next_entry(buf, fp, sizeof(u32)* 2);
    if ( rc < 0 )
        goto bad;

    if ( le32_to_cpu(buf[0]) != POLICYDB_MAGIC )
    {
        printk(KERN_ERR "Flask:  policydb magic number %#x does "
               "not match expected magic number %#x\n",
               le32_to_cpu(buf[0]), POLICYDB_MAGIC);
        goto bad;
    }

    len = le32_to_cpu(buf[1]);
    if ( len != strlen(POLICYDB_STRING) )
    {
        printk(KERN_ERR "Flask:  policydb string length %d does not "
               "match expected length %zu\n",
               len, strlen(POLICYDB_STRING));
        goto bad;
    }
    policydb_str = xmalloc_array(char, len + 1);
    if ( !policydb_str )
    {
        printk(KERN_ERR "Flask:  unable to allocate memory for policydb "
               "string of length %d\n", len);
        rc = -ENOMEM;
        goto bad;
    }
    rc = next_entry(policydb_str, fp, len);
    if ( rc < 0 )
    {
        printk(KERN_ERR "Flask:  truncated policydb string identifier\n");
        xfree(policydb_str);
        goto bad;
    }
    policydb_str[len] = 0;
    if ( strcmp(policydb_str, POLICYDB_STRING) == 0 )
        p->target_type = TARGET_XEN;
    else if ( strcmp(policydb_str, POLICYDB_STRING_OLD) == 0 )
        p->target_type = TARGET_XEN_OLD;
    else
    {
        printk(KERN_ERR "Flask: %s not a valid policydb string", policydb_str);
        xfree(policydb_str);
        goto bad;
    }
    /* Done with policydb_str. */
    xfree(policydb_str);
    policydb_str = NULL;

    /* Read the version, config, and table sizes. */
    rc = next_entry(buf, fp, sizeof(u32)*4);
    if ( rc < 0 )
        goto bad;

    p->policyvers = le32_to_cpu(buf[0]);
    if ( p->policyvers < POLICYDB_VERSION_MIN ||
                                        p->policyvers > POLICYDB_VERSION_MAX )
    {
            printk(KERN_ERR "Flask:  policydb version %d does not match "
                   "my version range %d-%d\n",
                   le32_to_cpu(buf[0]), POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
            goto bad;
    }

    if ( (le32_to_cpu(buf[1]) & POLICYDB_CONFIG_MLS) )
    {
        if ( ss_initialized && !flask_mls_enabled )
        {
            printk(KERN_ERR "Cannot switch between non-MLS and MLS "
                   "policies\n");
            goto bad;
        }
        flask_mls_enabled = 1;
        config |= POLICYDB_CONFIG_MLS;

        if ( p->policyvers < POLICYDB_VERSION_MLS )
        {
            printk(KERN_ERR "security policydb version %d (MLS) "
                   "not backwards compatible\n", p->policyvers);
            goto bad;
        }
    }
    else
    {
        if ( ss_initialized && flask_mls_enabled )
        {
            printk(KERN_ERR "Cannot switch between MLS and non-MLS "
                   "policies\n");
            goto bad;
        }
    }
    p->allow_unknown = !!(le32_to_cpu(buf[1]) & ALLOW_UNKNOWN);

    if ( p->policyvers >= POLICYDB_VERSION_POLCAP &&
         ebitmap_read(&p->policycaps, fp) != 0 )
        goto bad;

    if ( p->policyvers >= POLICYDB_VERSION_PERMISSIVE &&
         ebitmap_read(&p->permissive_map, fp) != 0 )
        goto bad;

    info = policydb_lookup_compat(p->policyvers, p->target_type);
    if ( !info )
    {
        printk(KERN_ERR "Flask:  unable to find policy compat info "
               "for version %d target %d\n", p->policyvers, p->target_type);
        goto bad;
    }

    if ( le32_to_cpu(buf[2]) != info->sym_num ||
         le32_to_cpu(buf[3]) != info->ocon_num )
    {
        printk(KERN_ERR "Flask:  policydb table sizes (%d,%d) do "
               "not match mine (%d,%d)\n", le32_to_cpu(buf[2]),
               le32_to_cpu(buf[3]),
               info->sym_num, info->ocon_num);
        goto bad;
    }

    for ( i = 0; i < info->sym_num; i++ )
    {
        rc = next_entry(buf, fp, sizeof(u32)*2);
        if ( rc < 0 )
            goto bad;
        nprim = le32_to_cpu(buf[0]);
        nel = le32_to_cpu(buf[1]);
        for ( j = 0; j < nel; j++ )
        {
            rc = read_f[i](p, p->symtab[i].table, fp);
            if ( rc )
                goto bad;
        }

        p->symtab[i].nprim = nprim;
    }

    rc = avtab_read(&p->te_avtab, fp, p);
    if ( rc )
        goto bad;

    if ( p->policyvers >= POLICYDB_VERSION_BOOL )
    {
        rc = cond_read_list(p, fp);
        if ( rc )
            goto bad;
    }

    rc = next_entry(buf, fp, sizeof(u32));
    if ( rc < 0 )
        goto bad;
    nel = le32_to_cpu(buf[0]);
    ltr = NULL;
    for ( i = 0; i < nel; i++ )
    {
        tr = xzalloc(struct role_trans);
        if ( !tr )
        {
            rc = -ENOMEM;
            goto bad;
        }
        if ( ltr )
            ltr->next = tr;
        else
            p->role_tr = tr;
        if ( p->policyvers >= POLICYDB_VERSION_ROLETRANS )
            rc = next_entry(buf, fp, sizeof(u32)*4);
        else
            rc = next_entry(buf, fp, sizeof(u32)*3);
        if ( rc < 0 )
            goto bad;
        tr->role = le32_to_cpu(buf[0]);
        tr->type = le32_to_cpu(buf[1]);
        tr->new_role = le32_to_cpu(buf[2]);
        if ( !policydb_role_isvalid(p, tr->role) ||
             !policydb_type_isvalid(p, tr->type) ||
             !policydb_role_isvalid(p, tr->new_role) )
        {
            rc = -EINVAL;
            goto bad;
        }
        ltr = tr;
    }

    rc = next_entry(buf, fp, sizeof(u32));
    if ( rc < 0 )
        goto bad;
    nel = le32_to_cpu(buf[0]);
    lra = NULL;
    for ( i = 0; i < nel; i++ )
    {
        ra = xzalloc(struct role_allow);
        if ( !ra )
        {
            rc = -ENOMEM;
            goto bad;
        }
        if ( lra )
            lra->next = ra;
        else
            p->role_allow = ra;
        rc = next_entry(buf, fp, sizeof(u32)*2);
        if ( rc < 0 )
            goto bad;
        ra->role = le32_to_cpu(buf[0]);
        ra->new_role = le32_to_cpu(buf[1]);
        if ( !policydb_role_isvalid(p, ra->role) ||
             !policydb_role_isvalid(p, ra->new_role) )
        {
            rc = -EINVAL;
            goto bad;
        }
        lra = ra;
    }

    if ( p->policyvers >= POLICYDB_VERSION_FILENAME_TRANS )
    {
        rc = next_entry(buf, fp, sizeof(u32));
        if ( rc )
            goto bad;
        nel = le32_to_cpu(buf[0]);
        if ( nel )
        {
            printk(KERN_ERR "Flask:  unsupported genfs config data\n");
            rc = -EINVAL;
            goto bad;
        }
    }

    rc = policydb_index_classes(p);
    if ( rc )
        goto bad;

    rc = policydb_index_others(p);
    if ( rc )
        goto bad;

    for ( i = 0; i < info->ocon_num; i++ )
    {
        rc = next_entry(buf, fp, sizeof(u32));
        if ( rc < 0 )
            goto bad;
        nel = le32_to_cpu(buf[0]);
        pn = &p->ocontexts[i];
        l = NULL;
        for ( j = 0; j < nel; j++ )
        {
            c = xzalloc(struct ocontext);
            if ( !c )
            {
                rc = -ENOMEM;
                goto bad;
            }
            rc = -EINVAL;
            switch ( i )
            {
            case OCON_ISID:
                rc = next_entry(buf, fp, sizeof(u32));
                if ( rc < 0 )
                    goto bad;
                c->sid = le32_to_cpu(buf[0]);
                rc = context_read_and_validate(&c->context, p, fp);
                if ( rc )
                    goto bad;
                break;
            case OCON_PIRQ:
                if ( p->target_type != TARGET_XEN )
                {
                    printk(KERN_ERR
                        "Old xen policy does not support pirqcon");
                    goto bad;
                }
                rc = next_entry(buf, fp, sizeof(u32));
                if ( rc < 0 )
                    goto bad;
                c->u.pirq = le32_to_cpu(buf[0]);
                rc = context_read_and_validate(&c->context, p, fp);
                if ( rc )
                    goto bad;
                break;
            case OCON_IOPORT:
                if ( p->target_type != TARGET_XEN )
                {
                    printk(KERN_ERR
                        "Old xen policy does not support ioportcon");
                    goto bad;
                }
                rc = next_entry(buf, fp, sizeof(u32) *2);
                if ( rc < 0 )
                    goto bad;
                c->u.ioport.low_ioport = le32_to_cpu(buf[0]);
                c->u.ioport.high_ioport = le32_to_cpu(buf[1]);
                rc = context_read_and_validate(&c->context, p, fp);
                if ( rc )
                    goto bad;

                if ( *pn || ( l && l->u.ioport.high_ioport >= c->u.ioport.low_ioport ) )
                {
                    pn = &p->ocontexts[i];
                    l = *pn;
                    while ( l && l->u.ioport.high_ioport < c->u.ioport.low_ioport ) {
                        pn = &l->next;
                        l = *pn;
                    }
                    c->next = l;
                }
                l = c;
                break;
            case OCON_IOMEM:
                if ( p->target_type != TARGET_XEN )
                {
                    printk(KERN_ERR
                        "Old xen policy does not support iomemcon");
                    goto bad;
                }
                if ( p->policyvers >= POLICYDB_VERSION_XEN_DEVICETREE )
                {
                    u64 b64[2];
                    rc = next_entry(b64, fp, sizeof(u64) *2);
                    if ( rc < 0 )
                        goto bad;
                    c->u.iomem.low_iomem = le64_to_cpu(b64[0]);
                    c->u.iomem.high_iomem = le64_to_cpu(b64[1]);
                }
                else
                {
                    rc = next_entry(buf, fp, sizeof(u32) *2);
                    if ( rc < 0 )
                        goto bad;
                    c->u.iomem.low_iomem = le32_to_cpu(buf[0]);
                    c->u.iomem.high_iomem = le32_to_cpu(buf[1]);
                }
                rc = context_read_and_validate(&c->context, p, fp);
                if ( rc )
                    goto bad;

                if ( *pn || ( l && l->u.iomem.high_iomem >= c->u.iomem.low_iomem ) )
                {
                    pn = &p->ocontexts[i];
                    l = *pn;
                    while ( l && l->u.iomem.high_iomem < c->u.iomem.low_iomem ) {
                        pn = &l->next;
                        l = *pn;
                    }
                    c->next = l;
                }
                l = c;
                break;
            case OCON_DEVICE:
                if ( p->target_type != TARGET_XEN )
                {
                    printk(KERN_ERR
                        "Old xen policy does not support pcidevicecon");
                    goto bad;
                }
                rc = next_entry(buf, fp, sizeof(u32));
                if ( rc < 0 )
                    goto bad;
                c->u.device = le32_to_cpu(buf[0]);
                rc = context_read_and_validate(&c->context, p, fp);
                if ( rc )
                    goto bad;
                break;
            case OCON_DTREE:
                if ( p->target_type != TARGET_XEN )
                {
                    printk(KERN_ERR
                        "Old xen policy does not support devicetreecon");
                    goto bad;
                }
                rc = next_entry(buf, fp, sizeof(u32));
                if ( rc < 0 )
                    goto bad;
                len = le32_to_cpu(buf[0]);
                rc = -ENOMEM;
                c->u.name = xmalloc_array(char, len + 1);
                if (!c->u.name)
                    goto bad;
                rc = next_entry(c->u.name, fp, len);
                if ( rc < 0 )
                    goto bad;
                c->u.name[len] = 0;
                rc = context_read_and_validate(&c->context, p, fp);
                if ( rc )
                    goto bad;
                break;
            default:
                printk(KERN_ERR
                       "Flask:  unsupported object context config data\n");
                rc = -EINVAL;
                goto bad;
            }

            *pn = c;
            pn = &c->next;
        }
    }

    rc = next_entry(buf, fp, sizeof(u32));
    if ( rc < 0 )
        goto bad;
    nel = le32_to_cpu(buf[0]);
    if ( nel )
    {
        printk(KERN_ERR "Flask:  unsupported genfs config data\n");
        rc = -EINVAL;
        goto bad;
    }

    if ( p->policyvers >= POLICYDB_VERSION_MLS )
    {
        int new_rangetr = p->policyvers >= POLICYDB_VERSION_RANGETRANS;
        rc = next_entry(buf, fp, sizeof(u32));
        if ( rc < 0 )
            goto bad;
        nel = le32_to_cpu(buf[0]);
        lrt = NULL;
        for ( i = 0; i < nel; i++ )
        {
            rt = xzalloc(struct range_trans);
            if ( !rt )
            {
                rc = -ENOMEM;
                goto bad;
            }
            if ( lrt )
                lrt->next = rt;
            else
                p->range_tr = rt;
            rc = next_entry(buf, fp, (sizeof(u32) * 2));
            if ( rc < 0 )
                goto bad;
            rt->source_type = le32_to_cpu(buf[0]);
            rt->target_type = le32_to_cpu(buf[1]);
            if ( new_rangetr )
            {
                rc = next_entry(buf, fp, sizeof(u32));
                if ( rc < 0 )
                    goto bad;
                rt->target_class = le32_to_cpu(buf[0]);
            } else
                rt->target_class = SECCLASS_DOMAIN;
            if ( !policydb_type_isvalid(p, rt->source_type) ||
                 !policydb_type_isvalid(p, rt->target_type) ||
                 !policydb_class_isvalid(p, rt->target_class) )
            {
                rc = -EINVAL;
                goto bad;
            }
            rc = mls_read_range_helper(&rt->target_range, fp);
            if ( rc )
                goto bad;
            if ( !mls_range_isvalid(p, &rt->target_range) )
            {
                printk(KERN_WARNING "Flask:  rangetrans:  invalid range\n");
                goto bad;
            }
            lrt = rt;
        }
    }

    p->type_attr_map = xmalloc_array(struct ebitmap, p->p_types.nprim);
    if ( !p->type_attr_map )
        goto bad;

    for ( i = 0; i < p->p_types.nprim; i++ )
    {
        ebitmap_init(&p->type_attr_map[i]);
        if ( p->policyvers >= POLICYDB_VERSION_AVTAB )
        {
            if ( ebitmap_read(&p->type_attr_map[i], fp) )
                goto bad;
        }
        /* add the type itself as the degenerate case */
        if ( ebitmap_set_bit(&p->type_attr_map[i], i, 1) )
                goto bad;
    }

    rc = policydb_bounds_sanity_check(p);
    if ( rc )
        goto bad;

    rc = 0;
out:
    return rc;
bad:
    if ( !rc )
        rc = -EINVAL;
    policydb_destroy(p);
    goto out;
}
