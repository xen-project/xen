/*
 * Implementation of the multi-level security (MLS) policy.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */

/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *    Support for enhanced MLS infrastructure.
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 */

/* Ported to Xen 3.0, George Coker, <gscoker@alpha.ncsc.mil> */

#include <xen/lib.h>
#include <xen/xmalloc.h>
#include <xen/string.h>
#include <xen/errno.h>
#include "sidtab.h"
#include "mls.h"
#include "policydb.h"
#include "services.h"

/*
 * Return the length in bytes for the MLS fields of the
 * security context string representation of `context'.
 */
int mls_compute_context_len(struct context * context)
{
    int i, l, len, head, prev;
    char *nm;
    struct ebitmap *e;
    struct ebitmap_node *node;

    if ( !flask_mls_enabled )
        return 0;

    len = 1; /* for the beginning ":" */
    for ( l = 0; l < 2; l++ )
    {
        int index_sens = context->range.level[l].sens;
        len += strlen(policydb.p_sens_val_to_name[index_sens - 1]);

        /* categories */
        head = -2;
        prev = -2;
        e = &context->range.level[l].cat;
        ebitmap_for_each_positive_bit(e, node, i)
        {
            if ( i - prev > 1 )
            {
				/* one or more negative bits are skipped */
                if ( head != prev )
                {
                    nm = policydb.p_cat_val_to_name[prev];
                    len += strlen(nm) + 1;
                }
                nm = policydb.p_cat_val_to_name[i];
                len += strlen(nm) + 1;
                head = i;
            }
            prev = i;
        }
        if ( prev != head )
        {
            nm = policydb.p_cat_val_to_name[prev];
            len += strlen(nm) + 1;
        }
        if ( l == 0 )
        {
            if ( mls_level_eq(&context->range.level[0], 
                              &context->range.level[1]) )
                break;
            else
                len++;
        }
    }

    return len;
}

/*
 * Write the security context string representation of
 * the MLS fields of `context' into the string `*scontext'.
 * Update `*scontext' to point to the end of the MLS fields.
 */
void mls_sid_to_context(struct context *context, char **scontext)
{
    char *scontextp, *nm;
    int i, l, head, prev;
    struct ebitmap *e;
    struct ebitmap_node *node;

    if ( !flask_mls_enabled )
        return;

    scontextp = *scontext;

    *scontextp = ':';
    scontextp++;

    for ( l = 0; l < 2; l++ )
    {
        memcpy(scontextp,
                policydb.p_sens_val_to_name[context->range.level[l].sens - 1],
                strlen(policydb.p_sens_val_to_name[context->range.level[l].sens - 1])+1);
        scontextp += strlen(scontextp);

        /* categories */
        head = -2;
        prev = -2;
        e = &context->range.level[l].cat;
        ebitmap_for_each_positive_bit(e, node, i)
        {
            if ( i - prev > 1 )
            {
                /* one or more negative bits are skipped */
                if ( prev != head )
                {
                    if ( prev - head > 1 )
                        *scontextp++ = '.';
                    else
                        *scontextp++ = ',';
                    nm = policydb.p_cat_val_to_name[prev];
                    memcpy(scontextp, nm, strlen(nm)+1);
                    scontextp += strlen(nm);
                }
                if ( prev < 0 )
                    *scontextp++ = ':';
                else
                    *scontextp++ = ',';
                nm = policydb.p_cat_val_to_name[i];
                memcpy(scontextp, nm, strlen(nm)+1);
                scontextp += strlen(nm);
                head = i;
            }
            prev = i;
        }

        if ( prev != head )
        {
            if ( prev - head > 1 )
                *scontextp++ = '.';
            else
                *scontextp++ = ',';
            nm = policydb.p_cat_val_to_name[prev];
            memcpy(scontextp, nm, strlen(nm)+1);
            scontextp += strlen(nm);
        }

        if ( l == 0 )
        {
            if ( mls_level_eq(&context->range.level[0],
                                                 &context->range.level[1]) )
                break;
            else
            {
                *scontextp = '-';
                scontextp++;
            }
        }
    }

    *scontext = scontextp;
    return;
}

int mls_level_isvalid(struct policydb *p, struct mls_level *l)
{
    struct level_datum *levdatum;
    struct ebitmap_node *node;
    int i;

    if ( !l->sens || l->sens > p->p_levels.nprim )
        return 0;
    levdatum = hashtab_search(p->p_levels.table,
                              p->p_sens_val_to_name[l->sens - 1]);
    if ( !levdatum )
        return 0;

    ebitmap_for_each_positive_bit(&l->cat, node, i)
    {
        if ( i > p->p_cats.nprim )
            return 0;
        if ( !ebitmap_get_bit(&levdatum->level->cat, i) )
        {
            /*
             * Category may not be associated with
             * sensitivity.
             */
            return 0;
        }
    }

    return 1;
}

int mls_range_isvalid(struct policydb *p, struct mls_range *r)
{
    return ( mls_level_isvalid(p, &r->level[0]) &&
             mls_level_isvalid(p, &r->level[1]) &&
             mls_level_dom(&r->level[1], &r->level[0]));
}

/*
 * Return 1 if the MLS fields in the security context
 * structure `c' are valid.  Return 0 otherwise.
 */
int mls_context_isvalid(struct policydb *p, struct context *c)
{
    struct user_datum *usrdatum;

    if ( !flask_mls_enabled )
        return 1;

    if ( !mls_range_isvalid(p, &c->range) )
        return 0;

    if ( c->role == OBJECT_R_VAL )
        return 1;

    /*
     * User must be authorized for the MLS range.
     */
    if ( !c->user || c->user > p->p_users.nprim )
        return 0;
    usrdatum = p->user_val_to_struct[c->user - 1];
    if ( !mls_range_contains(usrdatum->range, c->range) )
        return 0; /* user may not be associated with range */

    return 1;
}

/*
 * Set the MLS fields in the security context structure
 * `context' based on the string representation in
 * the string `*scontext'.  Update `*scontext' to
 * point to the end of the string representation of
 * the MLS fields.
 *
 * This function modifies the string in place, inserting
 * NULL characters to terminate the MLS fields.
 *
 * Policy read-lock must be held for sidtab lookup.
 *
 */
int mls_context_to_sid(char oldc, char **scontext,
                       struct context *context, struct sidtab *s)
{

    char delim;
    char *scontextp, *p, *rngptr;
    struct level_datum *levdatum;
    struct cat_datum *catdatum, *rngdatum;
    int l, rc = -EINVAL;

    if ( !flask_mls_enabled )
        return 0;

    /*
     * No MLS component to the security context -> error.
     */
    if ( !oldc )
        goto out;

    /* Extract low sensitivity. */
    scontextp = p = *scontext;
    while ( *p && *p != ':' && *p != '-' )
        p++;

    delim = *p;
    if ( delim != 0 )
        *p++ = 0;

    for ( l = 0; l < 2; l++ )
    {
        levdatum = hashtab_search(policydb.p_levels.table, scontextp);
        if ( !levdatum )
        {
            rc = -EINVAL;
            goto out;
        }

        context->range.level[l].sens = levdatum->level->sens;

        if ( delim == ':' )
        {
            /* Extract category set. */
            while ( 1 )
            {
                scontextp = p;
                while ( *p && *p != ',' && *p != '-' )
                    p++;
                delim = *p;
                if ( delim != 0 )
                    *p++ = 0;

                /* Separate into range if exists */
                if ( (rngptr = strchr(scontextp, '.')) != NULL )
                {
                    /* Remove '.' */
                    *rngptr++ = 0;
                }

                catdatum = hashtab_search(policydb.p_cats.table, scontextp);
                if ( !catdatum )
                {
                    rc = -EINVAL;
                    goto out;
                }

                rc = ebitmap_set_bit(&context->range.level[l].cat,
                                                    catdatum->value - 1, 1);
                if ( rc )
                    goto out;

                /* If range, set all categories in range */
                if ( rngptr )
                {
                    int i;

                    rngdatum = hashtab_search(policydb.p_cats.table, rngptr);
                    if ( !rngdatum )
                    {
                        rc = -EINVAL;
                        goto out;
                    }

                    if ( catdatum->value >= rngdatum->value )
                    {
                        rc = -EINVAL;
                        goto out;
                    }

                    for ( i = catdatum->value; i < rngdatum->value; i++ )
                    {
                        rc = ebitmap_set_bit(&context->range.level[l].cat, i, 1);
                        if ( rc )
                            goto out;
                    }
                }

                if ( delim != ',' )
                    break;
            }
        }
        if ( delim == '-' )
        {
            /* Extract high sensitivity. */
            scontextp = p;
            while ( *p && *p != ':' )
                p++;

            delim = *p;
            if ( delim != 0 )
                *p++ = 0;
        }
        else
            break;
    }

    if ( l == 0 )
    {
        context->range.level[1].sens = context->range.level[0].sens;
        rc = ebitmap_cpy(&context->range.level[1].cat,
                 &context->range.level[0].cat);
        if ( rc )
            goto out;
    }
    *scontext = ++p;
    rc = 0;
out:
    return rc;
}

/*
 * Copies the MLS range `range' into `context'.
 */
static inline int mls_range_set(struct context *context,
                                                    struct mls_range *range)
{
    int l, rc = 0;

    /* Copy the MLS range into the  context */
    for ( l = 0; l < 2; l++ )
    {
        context->range.level[l].sens = range->level[l].sens;
        rc = ebitmap_cpy(&context->range.level[l].cat,
                 &range->level[l].cat);
        if ( rc )
            break;
    }

    return rc;
}

/*
 * Convert the MLS fields in the security context
 * structure `c' from the values specified in the
 * policy `oldp' to the values specified in the policy `newp'.
 */
int mls_convert_context(struct policydb *oldp, struct policydb *newp,
                                                            struct context *c)
{
    struct level_datum *levdatum;
    struct cat_datum *catdatum;
    struct ebitmap bitmap;
    struct ebitmap_node *node;
    int l, i;

    if ( !flask_mls_enabled )
        return 0;

    for ( l = 0; l < 2; l++ )
    {
        levdatum = hashtab_search(newp->p_levels.table,
                        oldp->p_sens_val_to_name[c->range.level[l].sens - 1]);

        if ( !levdatum )
            return -EINVAL;
        c->range.level[l].sens = levdatum->level->sens;

        ebitmap_init(&bitmap);
        ebitmap_for_each_positive_bit(&c->range.level[l].cat, node, i)
        {
            int rc;

            catdatum = hashtab_search(newp->p_cats.table,
                                      oldp->p_cat_val_to_name[i]);
            if ( !catdatum )
                return -EINVAL;
            rc = ebitmap_set_bit(&bitmap, catdatum->value - 1, 1);
            if ( rc )
                return rc;
        }
        ebitmap_destroy(&c->range.level[l].cat);
        c->range.level[l].cat = bitmap;
    }

    return 0;
}

int mls_compute_sid(struct context *scontext, struct context *tcontext,
                        u16 tclass, u32 specified, struct context *newcontext)
{
    struct range_trans *rtr;

    if ( !flask_mls_enabled )
        return 0;

    switch ( specified )
    {
        case AVTAB_TRANSITION:
            /* Look for a range transition rule. */
            for (rtr = policydb.range_tr; rtr; rtr = rtr->next)
            {
                if (rtr->source_type == scontext->type &&
                    rtr->target_type == tcontext->type &&
                    rtr->target_class == tclass)
                {
                    /* Set the range from the rule */
                    return mls_range_set(newcontext,
                                         &rtr->target_range);
                }
            }
            /* Fallthrough */
        case AVTAB_CHANGE:
            if ( tclass == SECCLASS_DOMAIN )
                /* Use the process MLS attributes. */
                return mls_context_cpy(newcontext, scontext);
            else
                /* Use the process effective MLS attributes. */
                return mls_context_cpy_low(newcontext, scontext);
        case AVTAB_MEMBER:
            /* Use the process effective MLS attributes. */
            return mls_context_cpy_low(newcontext, scontext);
        default:
            return -EINVAL;
    }
    return -EINVAL;
}

