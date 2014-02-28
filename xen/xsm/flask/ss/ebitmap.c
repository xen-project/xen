/*
 * Implementation of the extensible bitmap type.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
/*
 * Updated: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *      Applied standard bit operations to improve bitmap scanning.
 */

/* Ported to Xen 3.0, George Coker, <gscoker@alpha.ncsc.mil> */

#include <asm/byteorder.h>
#include <xen/lib.h>
#include <xen/xmalloc.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/bitmap.h>
#include "ebitmap.h"
#include "policydb.h"

int ebitmap_cmp(struct ebitmap *e1, struct ebitmap *e2)
{
    struct ebitmap_node *n1, *n2;

    if ( e1->highbit != e2->highbit )
        return 0;

    n1 = e1->node;
    n2 = e2->node;
    while ( n1 && n2 && (n1->startbit == n2->startbit) &&
            !memcmp(n1->maps, n2->maps, EBITMAP_SIZE / 8))
    {
        n1 = n1->next;
        n2 = n2->next;
    }

    if ( n1 || n2 )
        return 0;

    return 1;
}

int ebitmap_cpy(struct ebitmap *dst, struct ebitmap *src)
{
    struct ebitmap_node *n, *new, *prev;

    ebitmap_init(dst);
    n = src->node;
    prev = NULL;
    while ( n )
    {
        new = xzalloc(struct ebitmap_node);
        if ( !new )
        {
            ebitmap_destroy(dst);
            return -ENOMEM;
        }
        new->startbit = n->startbit;
        memcpy(new->maps, n->maps, EBITMAP_SIZE / 8);
        new->next = NULL;
        if ( prev )
            prev->next = new;
        else
            dst->node = new;
        prev = new;
        n = n->next;
    }

    dst->highbit = src->highbit;
    return 0;
}

int ebitmap_contains(struct ebitmap *e1, struct ebitmap *e2)
{
    struct ebitmap_node *n1, *n2;
    int i;

    if ( e1->highbit < e2->highbit )
        return 0;

    n1 = e1->node;
    n2 = e2->node;
    while ( n1 && n2 && (n1->startbit <= n2->startbit) )
    {
        if ( n1->startbit < n2->startbit )
        {
            n1 = n1->next;
            continue;
        }
        for ( i = 0; i < EBITMAP_UNIT_NUMS; i++ )
        {
            if ( (n1->maps[i] & n2->maps[i]) != n2->maps[i] )
                return 0;
        }

        n1 = n1->next;
        n2 = n2->next;
    }

    if ( n2 )
        return 0;

    return 1;
}

int ebitmap_get_bit(struct ebitmap *e, unsigned long bit)
{
    struct ebitmap_node *n;

    if ( e->highbit < bit )
        return 0;

    n = e->node;
    while ( n && (n->startbit <= bit) )
    {
        if ( (n->startbit + EBITMAP_SIZE) > bit )
            return ebitmap_node_get_bit(n, bit);
        n = n->next;
    }

    return 0;
}

int ebitmap_set_bit(struct ebitmap *e, unsigned long bit, int value)
{
    struct ebitmap_node *n, *prev, *new;

    prev = NULL;
    n = e->node;
    while ( n && n->startbit <= bit )
    {
        if ( (n->startbit + EBITMAP_SIZE) > bit )
        {
            if ( value )
            {
                ebitmap_node_set_bit(n, bit);
            }
            else
            {
                unsigned int s;

                ebitmap_node_clr_bit(n, bit);

                s = find_first_bit(n->maps, EBITMAP_SIZE);
                if ( s < EBITMAP_SIZE )
                    return 0;

                /* drop this node from the bitmap */

                if ( !n->next )
                {
                    /*
                     * this was the highest map
                     * within the bitmap
                     */
                    if ( prev )
                        e->highbit = prev->startbit + EBITMAP_SIZE;
                    else
                        e->highbit = 0;
                }
                if ( prev )
                    prev->next = n->next;
                else
                    e->node = n->next;

                xfree(n);
            }
            return 0;
        }
        prev = n;
        n = n->next;
    }

    if ( !value )
        return 0;

    new = xzalloc(struct ebitmap_node);
    if ( !new )
        return -ENOMEM;

    new->startbit = bit - (bit % EBITMAP_SIZE);
    ebitmap_node_set_bit(new, bit);

    if ( !n )
        /* this node will be the highest map within the bitmap */
        e->highbit = new->startbit + EBITMAP_SIZE;

    if ( prev )
    {
        new->next = prev->next;
        prev->next = new;
    }
    else
    {
        new->next = e->node;
        e->node = new;
    }

    return 0;
}

void ebitmap_destroy(struct ebitmap *e)
{
    struct ebitmap_node *n, *temp;

    if ( !e )
        return;

    n = e->node;
    while ( n )
    {
        temp = n;
        n = n->next;
        xfree(temp);
    }

    e->highbit = 0;
    e->node = NULL;
    return;
}

int ebitmap_read(struct ebitmap *e, void *fp)
{
    struct ebitmap_node *n = NULL;
    u32 mapunit, count, startbit, index;
    u64 map;
    __le32 buf[3];
    int rc, i;

    ebitmap_init(e);

    rc = next_entry(buf, fp, sizeof buf);
    if ( rc < 0 )
        goto out;

    mapunit = le32_to_cpu(buf[0]);
    e->highbit = le32_to_cpu(buf[1]);
    count = le32_to_cpu(buf[2]);

    if ( mapunit != sizeof(u64) * 8 )
    {
        printk(KERN_ERR "Flask: ebitmap: map size %u does not "
               "match my size %Zd (high bit was %d)\n", mapunit,
               sizeof(u64) * 8, e->highbit);
        goto bad;
    }

    /* round up e->highbit */
    e->highbit += EBITMAP_SIZE - 1;
    e->highbit -= (e->highbit % EBITMAP_SIZE);

    if ( !e->highbit )
    {
        e->node = NULL;
        goto ok;
    }

    for ( i = 0; i < count; i++ )
    {
        rc = next_entry(&startbit, fp, sizeof(u32));
        if ( rc < 0 )
        {
            printk(KERN_ERR "Flask: ebitmap: truncated map\n");
            goto bad;
        }
        startbit = le32_to_cpu(startbit);
        if ( startbit & (mapunit - 1) )
        {
            printk(KERN_ERR "Flask: ebitmap start bit (%d) is "
                   "not a multiple of the map unit size (%u)\n",
                   startbit, mapunit);
            goto bad;
        }
        if ( startbit > e->highbit - mapunit )
        {
            printk(KERN_ERR "Flask: ebitmap start bit (%d) is "
                   "beyond the end of the bitmap (%u)\n",
                   startbit, (e->highbit - mapunit));
            goto bad;
        }

        if ( !n || startbit >= n->startbit + EBITMAP_SIZE )
        {
            struct ebitmap_node *tmp = xzalloc(struct ebitmap_node);

            if ( !tmp )
            {
                printk(KERN_ERR
                       "Flask: ebitmap: out of memory\n");
                rc = -ENOMEM;
                goto bad;
            }
            /* round down */
            tmp->startbit = startbit - (startbit % EBITMAP_SIZE);
            if ( n )
                n->next = tmp;
            else
                e->node = tmp;
            n = tmp;
        }
        else if ( startbit <= n->startbit )
        {
            printk(KERN_ERR "Flask: ebitmap: start bit %d"
                   " comes after start bit %d\n",
                   startbit, n->startbit);
            goto bad;
        }

        rc = next_entry(&map, fp, sizeof(u64));
        if ( rc < 0 )
        {
            printk(KERN_ERR "Flask: ebitmap: truncated map\n");
            goto bad;
        }
        map = le64_to_cpu(map);

        index = (startbit - n->startbit) / EBITMAP_UNIT_SIZE;
        while ( map )
        {
            n->maps[index++] = map & (-1UL);
            map = EBITMAP_SHIFT_UNIT_SIZE(map);
        }
    }
ok:
    rc = 0;
out:
    return rc;
bad:
    if ( !rc )
        rc = -EINVAL;
    ebitmap_destroy(e);
    goto out;
}
