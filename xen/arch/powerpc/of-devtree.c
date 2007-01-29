/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * This code is intended to be used but relocatable routines So PLEASE
 * do not place any global data here including const integrals or
 * literals.
 * The local assert() is ok for string literal usage.. but thats it.
 */


#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include "of-devtree.h"

static int (*ofd_write)(const char *, size_t len) = NULL;

void ofd_init(int (*write)(const char *, size_t len))
{
    ofd_write = write;
}
                  

static void ofd_stop(void)
{
    for ( ; ; ) ;
}

/* this is so it can be called from anywhere */
static void ofd_assprint(int line)
{
    char a[13];
    char num[20];
    int i;

    a[0]  = '\n';
    a[1]  = '\n';
    a[2]  = 'O';
    a[3]  = 'F';
    a[4]  = 'D';
    a[5]  = ':';
    a[6]  = 'A';
    a[7]  = 'S';
    a[8]  = 'S';
    a[9]  = 'E';
    a[10] = 'R';
    a[11] = 'T';
    a[12] = ':';


    ofd_write(a, sizeof (a) - 1);
    
    /* put the number in backwards */
    i = 0;
    while ( line > 0 ) {
        num[i++] = '0' + (line % 10);
        line /= 10;
    }
    /* print it */
    /* number */
    while (i-- > 0) {
        ofd_write(&num[i], 1);
    }
    ofd_write("\n", 1);

    ofd_stop();
}

#ifdef assert
#undef assert
#endif

#define assert(EX)                                              \
    do {                                                        \
        if ( !(EX) ) {                                          \
            ofd_assprint(__LINE__);                             \
        }                                                       \
    } while (0)

/*
 * We treat memory like an array of u64.  For the sake of
 * compactness we assume that a short is big enough as an index.
 */
struct ofd_node {
    ofdn_t on_ima;
    ofdn_t on_parent;
    ofdn_t on_child;
    ofdn_t on_peer;
    ofdn_t on_io;
    ofdn_t on_next;     /* for search lists */
    ofdn_t on_prev;
    ofdn_t on_prop;
    u32 on_pathlen;
    u32 on_last;
    char on_path[0];
};

struct ofd_prop {
    ofdn_t op_ima;
    ofdn_t op_next;
    u32 op_objsz;
    u32 op_namesz;
    /* must have 64bit alignment */
    char op_data[0]  __attribute__ ((aligned(8)));
};

struct ofd_io {
    ofdn_t oi_ima;
    ofdn_t oi_node;
    u64 oi_open   __attribute__ ((aligned(8)));
};

struct ofd_free {
    ofdn_t of_cells;
    ofdn_t of_next;
};

struct ofd_mem {
    ofdn_t om_num;
    ofdn_t om_next;
    ofdn_t om_free;     /* Future site of a free list */
    ofdn_t _om_pad;
    u64 om_mem[0] __attribute__((aligned(8)));
};

#define NODE_PAT    0x0f01
#define PROP_PAT    0x0f03
#define IO_PAT      0x0f05


size_t ofd_size(void *mem)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    size_t sz;

    sz = m->om_next * sizeof (u64) + sizeof(*m);
    return sz;
}

size_t ofd_space(void *mem)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    size_t sz;

    sz = m->om_num * sizeof (u64);
    return sz;
}


static int ofd_pathsplit_right(const char *s, int c, size_t max)
{
    int i = 0;

    if ( max == 0 ) {
        --max;
    }
    
    while ( *s != '\0' && *s != c && max != 0 ) {
        ++i;
        ++s;
        --max;
    }
    return i;
}

static int ofd_pathsplit_left(const char *p, int c, size_t len)
{
    const char *s;

    if ( len > 0 ) {
        /* move s to the end */
        s = p + len - 1;

        /* len could include a null */
        if ( *s == '\0' ) {
            --s;
        }
        while ( s >= p ) {
            if ( *s == c ) {
                ++s;
                break;
            }
            --s;
        }
        if ( s < p ) {
            return 0;
        }
        return (s - p);
    }
    return 0;
}

void *ofd_create(void *mem, size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *n;
    size_t sum;
    ofdn_t cells;

    if ( sz < (sizeof (*n) * 4) ) {
        return NULL;
    }

    memset(mem, 0, sz);

    m->om_num = (sz - sizeof(*m)) / sizeof (u64);

    /* skip the first cell */
    m->om_next = OFD_ROOT;
    n = (struct ofd_node *)&m->om_mem[m->om_next];
    n->on_ima = NODE_PAT;
    n->on_pathlen = 2;
    n->on_last = 1;
    n->on_path[0] = '/';
    n->on_path[1] = '\0';

    sum = sizeof (*n) + 2; /* Don't forget the path */
    cells = (sum + sizeof (m->om_mem[0]) - 1) / sizeof (m->om_mem[0]);
    m->om_next += cells;

    return m;
}

static struct ofd_node *ofd_node_get(struct ofd_mem *m, ofdn_t n)
{
    if ( n < m->om_next ) {
        struct ofd_node *r;

        r = (struct ofd_node *)&m->om_mem[n];
        if ( r->on_ima == NODE_PAT ) {
            return r;
        }
    }
    return NULL;
}

ofdn_t ofd_node_parent(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r = ofd_node_get(m, n);

    if ( r == NULL) return 0;
    return r->on_parent;
}

ofdn_t ofd_node_peer(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r;

    if ( n == 0 ) {
        return OFD_ROOT;
    }

    r = ofd_node_get(m, n);
    if ( r == NULL) return 0;
    return r->on_peer;
}

const char *ofd_node_path(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r = ofd_node_get(m, n);

    if ( r == NULL) return NULL;
    return r->on_path;
}

static ofdn_t ofd_node_prop(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r = ofd_node_get(m, n);

    if ( r == NULL) return 0;
    return r->on_prop;
}

ofdn_t ofd_node_child(void *mem, ofdn_t p)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r = ofd_node_get(m, p);

    if ( r == NULL) return 0;
    return r->on_child;
}

int ofd_node_to_path(void *mem, ofdn_t p, void *buf, size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r = ofd_node_get(m, p);

    if ( sz > r->on_pathlen ) {
        sz = r->on_pathlen;
    }

    memcpy(buf, r->on_path, sz);

    if ( r == NULL) return -1;
    return r->on_pathlen;
}

static int ofd_check(void *p, size_t l)
{
    int i;
    u64 *v = (u64 *)p;

    for ( i = 0; i < l; i++ ) {
        if ( v[i] != 0ULL ) {
            return 0;
        }
    }
    return 1;
}



static ofdn_t ofd_node_create(
    struct ofd_mem *m, const char *path, size_t pathlen)
{
    struct ofd_node *n;
    ofdn_t pos;
    size_t sum = pathlen + 1 + sizeof (*n); /* add trailing zero to path */
    ofdn_t cells = (sum + sizeof(m->om_mem[0]) - 1) / sizeof(m->om_mem[0]);

    if ( m->om_next + cells >= m->om_num ) {
        return 0;
    }

    pos = m->om_next;
        
    assert(ofd_check(&m->om_mem[pos], cells)); /* non-zero */
    m->om_next += cells;

    n = (struct ofd_node *)&m->om_mem[pos];
    assert(n->on_ima == 0); /* new node not empty */

    n->on_ima = NODE_PAT;
    n->on_peer = 0;
    n->on_child = 0;
    n->on_io = 0;
    n->on_pathlen = pathlen;
    n->on_last = ofd_pathsplit_left(path, '/', pathlen);
    strlcpy(n->on_path, path, pathlen);

    return pos;
}

/* prunes a node and all its children simply by wasting memory and
 * unlinking it from the tree */
int ofd_node_prune(void *mem, ofdn_t node)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *n;
    struct ofd_node *p;

    n = ofd_node_get(m, node);
    if (n == NULL) return -1;

    p = ofd_node_get(m, n->on_parent);
    assert(p != NULL);

    if ( p->on_child == node ) {
        /* easy case */
        p->on_child = n->on_peer;
    } else {
        struct ofd_node *s;

        s = ofd_node_get(m, p->on_child);
        assert(s != NULL);
        while ( s->on_peer != node ) {
            s = ofd_node_get(m, s->on_peer);
            assert(s != NULL);
        }
        s->on_peer = n->on_peer;
    }
    return 1;
}

ofdn_t ofd_prune_path(void *m, const char *path)
{
    ofdn_t n;
    int rc = -1;
    while ((n = ofd_node_find(m, path)) > 0) {
        rc = ofd_node_prune(m, n);
    }

    return rc;
}

ofdn_t ofd_node_child_create(
    void *mem, ofdn_t parent, const char *path, size_t pathlen)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *p;
    struct ofd_node *n;
    ofdn_t pos;

    p = ofd_node_get(m, parent);
    if (p == NULL) return  0;

    pos = ofd_node_create(m, path, pathlen);
    n = ofd_node_get(m, pos);
    assert(n != NULL);

    assert(p->on_child == 0); /* child exists */
    if ( p->on_child == 0 ) {
        p->on_child = pos;
        n->on_parent = parent;
    } else {
        pos = 0;
    }

    return pos;
}

ofdn_t ofd_node_peer_create(
    void *mem, ofdn_t sibling, const char *path, size_t pathlen)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *s;
    struct ofd_node *n;
    ofdn_t pos;

    s = ofd_node_get(m, sibling);
    if (s == NULL) return 0;

    pos = ofd_node_create(m, path, pathlen);
    n = ofd_node_get(m, pos);
    assert(n != NULL);

    if ( s->on_peer == 0 ) {
        s->on_peer = pos;
        n->on_parent = s->on_parent;
    } else {
        assert(0); /* peer exists */
        pos = 0;
    }
    return pos;
}

static ofdn_t ofd_node_peer_last(void *mem, ofdn_t c)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *n;

    n = ofd_node_get(m, c);
    if (n == NULL) return 0;

    while ( n->on_peer > 0 ) {
        c = n->on_peer;
        n = ofd_node_get(m, c);
        assert(n != NULL);
    }

    return c;
}

static ofdn_t ofd_node_walk(struct ofd_mem *m, ofdn_t p, const char *s)
{
    struct ofd_node *np;
    ofdn_t n;
    ofdn_t r;

    if ( *s == '/' ) {
        ++s;
        if ( *s == '\0' ) {
            assert(0); /* ends in / */
            return 0;
        }
    }

    np = ofd_node_get(m, p);
    if (np == NULL) return 0;

    r = p;
    do {
        int last = np->on_last;
        size_t lsz = np->on_pathlen - last;
        size_t sz;

        sz = ofd_pathsplit_right(s, '/', 0);
        
        if ( lsz > 0 && strncmp(s, &np->on_path[last], sz) == 0 ) {
            if ( s[sz] == '\0' ) {
                return r;
            }
            /* there is more to the path */
            n = ofd_node_child(m, p);
            if ( n != 0 ) {
                r = ofd_node_walk(m, n, &s[sz]);
                return r;
            }
            /* there are no children */
            return 0;
        }
    } while ( 0 );

    /*
     * we know that usually we are only serching for top level peers
     * so we do peers first peer
     */
    n = ofd_node_peer(m, p);
    if ( n > 0 ) {
        r = ofd_node_walk(m, n, s);
    } else {
        r = 0;
    }

    return r;
}


ofdn_t ofd_node_find(void *mem, const char *devspec)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t n = OFD_ROOT;
    const char *s = devspec;
    size_t sz;

    if ( s == NULL || s[0] == '\0' ) {
        return OFD_ROOT;
    }

    if ( s[0] != '/' ) {
        size_t asz;

        /* get the component length */
        sz = ofd_pathsplit_right(s, '/', 0);

        /* check for an alias */
        asz = ofd_pathsplit_right(s, ':', sz);

        if ( s[asz] == ':' ) {
            /*
             * s points to an alias and &s[sz] points to the alias
             * args.
             */
            assert(0); /* aliases no supported */
            return 0;
        }
    } else if ( s[1] == '\0' ) {
        return n;
    }

    n = ofd_node_child(m, n);
    if ( n == 0 ) {
        return 0;
    }

    return ofd_node_walk(m, n, s);
}


static struct ofd_prop *ofd_prop_get(struct ofd_mem *m, ofdn_t p)
{
    if ( p < m->om_next ) {
        struct ofd_prop *r;

        r = (struct ofd_prop *)&m->om_mem[p];
        if ( r->op_ima == PROP_PAT ) {
            return r;
        }
        assert(r->op_ima == PROP_PAT); /* bad object */
    }
    return NULL;
}

static ofdn_t ofd_prop_create(
    struct ofd_mem *m,
    ofdn_t node,
    const char *name,
    const void *src,
    size_t sz)
{
    struct ofd_node *n;
    struct ofd_prop *p;
    size_t len = strlen(name) + 1;
    size_t sum = sizeof (*p) + sz + len;
    ofdn_t cells;
    char *dst;
    ofdn_t pos;

    cells = (sum + sizeof (m->om_mem[0]) - 1) / sizeof (m->om_mem[0]);

    if ( m->om_next + cells >= m->om_num ) {
        return 0;
    }

    /* actual data structure */
    pos = m->om_next;
    assert(ofd_check(&m->om_mem[pos], cells)); /* non-zero */

    p = (struct ofd_prop *)&m->om_mem[pos];
    m->om_next += cells;

    assert(p->op_ima == 0); /* new node not empty */
    p->op_ima = PROP_PAT;
    p->op_next = 0;
    p->op_objsz = sz;
    p->op_namesz = len;

    /* the rest of the data */
    dst = p->op_data;

    /* zero what will be the pad, cheap and cannot hurt */
    m->om_mem[m->om_next - 1] = 0;

    if ( sz > 0 ) {
        /* some props have no data, just a name */
        memcpy(dst, src, sz);
        dst += sz;
    }

    memcpy(dst, name, len);

    /* now place it in the tree */
    n = ofd_node_get(m, node);
    assert(n != NULL);

    if ( n->on_prop == 0 ) {
        n->on_prop = pos;
    } else {
        ofdn_t pn = n->on_prop;
        struct ofd_prop *nxt;

        for (;;) {
            nxt = ofd_prop_get(m, pn);
            if (nxt->op_next == 0) {
                nxt->op_next = pos;
                break;
            }
            pn = nxt->op_next;
        }
    }

    return pos;
}

void ofd_prop_remove(void *mem, ofdn_t node, ofdn_t prop)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *n = ofd_node_get(m, node);
    struct ofd_prop *p = ofd_prop_get(m, prop);

    if (n == NULL) return;
    if (p == NULL) return;

    if ( n->on_prop == prop ) {
        n->on_prop = p->op_next;
    } else {
        ofdn_t pn = n->on_prop;
        struct ofd_prop *nxt;

        for ( ; ; ) {
            nxt = ofd_prop_get(m, pn);
            if ( nxt->op_next == prop ) {
                nxt->op_next = p->op_next;
                break;
            }
            pn = nxt->op_next;
        }
    }
    return;
}

ofdn_t ofd_prop_find(void *mem, ofdn_t n, const char *name)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t p = ofd_node_prop(m, n);
    struct ofd_prop *r;
    char *s;
    size_t len;

    if ( name == NULL || *name == '\0' ) {
        return OFD_ROOT;
    }

    len = strlen(name) + 1;
    
    while ( p != 0 ) {
        r = ofd_prop_get(m, p);
        s = &r->op_data[r->op_objsz];
        if ( len == r->op_namesz ) {
            if ( strncmp(name, s, r->op_namesz) == 0 ) {
                break;
            }
        }
        p = r->op_next;
    }
    return p;
}

static ofdn_t ofd_prop_next(struct ofd_mem *m, ofdn_t n, const char *prev)
{
    ofdn_t p;

    if ( prev == NULL || *prev == '\0' ) {
        /* give the first */
        p = ofd_node_prop(m, n);
    } else {
        struct ofd_prop *r;

        /* look for the name */
        p = ofd_prop_find(m, n, prev);
        if ( p != 0 ) {
            /* get the data for prev */
            r = ofd_prop_get(m, p);

            /* now get next */
            p = r->op_next;
        } else {
            p = -1;
        }
    }

    return p;
}

ofdn_t ofd_nextprop(void *mem, ofdn_t n, const char *prev, char *name)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t p = ofd_prop_next(m, n, prev);
    struct ofd_prop *r;
    char *s;

    if ( p > 0 ) {
        r = ofd_prop_get(m, p);
        s = &r->op_data[r->op_objsz];
        memcpy(name, s, r->op_namesz);
    }

    return p;
}

/*
 * It is valid to call with NULL pointers, in case you want only one
 * cell size.
 */
int ofd_getcells(void* mem, ofdn_t n, u32* addr_cells, u32* size_cells)
{
    if ( addr_cells != NULL ) *addr_cells = 0;
    if ( size_cells != NULL ) *size_cells = 0;

retry:
    if ( addr_cells  != NULL && *addr_cells == 0 ) {
        ofd_getprop(mem, n, "#address-cells",
                addr_cells, sizeof(u32));
    }

    if ( size_cells != NULL && *size_cells == 0 ) {
        ofd_getprop(mem, n, "#size-cells", size_cells, sizeof(u32));
    }

    if ( ( size_cells != NULL && *size_cells == 0 )
            || ( addr_cells != NULL && *addr_cells == 0 ) ) {
        if ( n != OFD_ROOT ) {
            n = ofd_node_parent(mem, n);
            goto retry;
        }
        return -1;
    }

    return 1;
}

int ofd_getprop(void *mem, ofdn_t n, const char *name, void *buf, size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t p = ofd_prop_find(m, n, name);
    struct ofd_prop *r;

    if ( p == 0 ) {
        return -1;
    }

    r = ofd_prop_get(m, p);

    if ( sz > r->op_objsz ) {
        sz = r->op_objsz;
    }
    memcpy(buf, r->op_data, sz);

    return r->op_objsz;
}

int ofd_getproplen(void *mem, ofdn_t n, const char *name)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t p = ofd_prop_find(m, n, name);
    struct ofd_prop *r;

    if ( p == 0 ) {
        return -1;
    }

    r = ofd_prop_get(m, p);

    return r->op_objsz;
}

static ofdn_t ofd_prop_set(
    void *mem, ofdn_t n, const char *name, const void *src, size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t p = ofd_prop_find(m, n, name);
    struct ofd_prop *r;
    char *dst;

    r = ofd_prop_get(m, p);

    if ( sz <= r->op_objsz ) {
        /* we can reuse */
        memcpy(r->op_data, src, sz);
        if ( sz < r->op_objsz ) {
            /* need to move name */
            dst = r->op_data + sz;
            /*
             * use the name arg size we may have overlap with the
             * original
             */
            memcpy(dst, name, r->op_namesz);
            r->op_objsz = sz;
        }
    } else {
        /*
         * Sadly, we remove from the list, wasting the space and then
         * we can creat a new one
         */
        ofd_prop_remove(m, n, p);
        p = ofd_prop_create(mem, n, name, src, sz);
    }

    return p;
}

int ofd_setprop(
    void *mem, ofdn_t n, const char *name, const void *buf, size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t r;

    r = ofd_prop_find(m, n, name);
    if ( r == 0 ) {
        r = ofd_prop_create(mem, n, name, buf, sz);
    } else {
        r = ofd_prop_set(mem, n, name, buf, sz);
    }

    if ( r > 0 ) {
        struct ofd_prop *pp = ofd_prop_get(m, r);
        return pp->op_objsz;
    }

    return OF_FAILURE;
}


static ofdn_t ofd_find_by_prop(
    struct ofd_mem *m,
    ofdn_t head,
    ofdn_t *prev_p,
    ofdn_t n,
    const char *name,
    const void *val,
    size_t sz)
{
    struct ofd_node *np;
    struct ofd_prop *pp;
    ofdn_t p;

retry:
    p = ofd_prop_find(m, n, name);

    if ( p > 0 ) {
        int match = 0;

        /* a property exists by that name */
        if ( val == NULL ) {
            match = 1;
        } else {
            /* need to compare values */
            pp = ofd_prop_get(m, p);
            if ( sz == pp->op_objsz
                 && memcmp(pp->op_data, val, sz) == 0 ) {
                match = 1;
            }
        }
        if ( match == 1 ) {
            if ( *prev_p >= 0 ) {
                np = ofd_node_get(m, *prev_p);
                np->on_next = n;
            } else {
                head = n;
            }
            np = ofd_node_get(m, n);
            np->on_prev = *prev_p;
            np->on_next = -1;
            *prev_p = n;
        }
    }

    p = ofd_node_child(m, n);
    if ( p > 0 ) {
        head = ofd_find_by_prop(m, head, prev_p, p, name, val, sz);
    }

    p = ofd_node_peer(m, n);
    if ( p > 0 ) {
        n = p;
        goto retry;
    }

    return head;
}

ofdn_t ofd_node_find_by_prop(
    void *mem,
    ofdn_t n,
    const char *name,
    const void *val,
    size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;

    if ( n <= 0 ) {
        n = OFD_ROOT;
    }

    ofdn_t prev = -1;
    return ofd_find_by_prop(m, -1, &prev, n, name, val, sz);
}

ofdn_t ofd_node_find_next(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *np;

    np = ofd_node_get(m, n);

    if (np == NULL) return 0;
    return np->on_next;
}

ofdn_t ofd_node_find_prev(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *np;

    np = ofd_node_get(m, n);
    if (np == NULL) return 0;

    return np->on_prev;
}

ofdn_t ofd_io_create(void *mem, ofdn_t node, u64 open)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *n;
    struct ofd_io *i;
    ofdn_t pos;
    ofdn_t cells;

    cells = (sizeof (*i) + sizeof (m->om_mem[0]) - 1) / sizeof(m->om_mem[0]);

    n = ofd_node_get(m, node);
    if ( n == NULL ) return 0;

    if ( m->om_next + cells >= m->om_num ) {
        return 0;
    }

    pos = m->om_next;
    assert(ofd_check(&m->om_mem[pos], cells)); /* non-zero */

    m->om_next += cells;
    
    i = (struct ofd_io *)&m->om_mem[pos];
    assert(i->oi_ima == 0); /* new node not empty */

    i->oi_ima = IO_PAT;
    i->oi_node = node;
    i->oi_open = open;

    n->on_io = pos;

    return pos;
}

static struct ofd_io *ofd_io_get(struct ofd_mem *m, ofdn_t i)
{
    if ( i < m->om_next ) {
        struct ofd_io *r;

        r = (struct ofd_io *)&m->om_mem[i];
        if ( r->oi_ima == IO_PAT ) {
            return r;
        }
        assert(r->oi_ima == IO_PAT); /* bad object */
    }

    return NULL;
}

ofdn_t ofd_node_io(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_node *r = ofd_node_get(m, n);

    if (r == NULL) return 0;
    return r->on_io;
}

uint ofd_io_open(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_io *r = ofd_io_get(m, n);

    if (r == NULL) return 0;
    return r->oi_open;
}

void ofd_io_close(void *mem, ofdn_t n)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    struct ofd_io *o = ofd_io_get(m, n);
    struct ofd_node *r = ofd_node_get(m, o->oi_node);

    assert(o != NULL);
    assert(r != NULL);
    o->oi_open = 0;
    r->on_io = 0;
}

ofdn_t ofd_node_add(void *m, ofdn_t p, const char *path, size_t sz)
{
    ofdn_t n;

    n = ofd_node_child(m, p);
    if ( n > 0 ) {
        n = ofd_node_peer_last(m, n);
        if ( n > 0 ) {
            n = ofd_node_peer_create(m, n, path, sz);
        }
    } else {
        n = ofd_node_child_create(m, p, path, sz);
    }

    return n;
}

ofdn_t ofd_prop_add(
    void *mem,
    ofdn_t n,
    const char *name,
    const void *buf,
    size_t sz)
{
    struct ofd_mem *m = (struct ofd_mem *)mem;
    ofdn_t r;

    r = ofd_prop_find(m, n, name);
    if ( r == 0 ) {
        r = ofd_prop_create(mem, n, name, buf, sz);
    } else {
        r = ofd_prop_set(mem, n, name, buf, sz);
    }

    return r;
}
