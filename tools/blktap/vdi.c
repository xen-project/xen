/**************************************************************************
 * 
 * vdi.c
 *
 * Virtual Disk Image (VDI) Interfaces
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include "blockstore.h"
#include "radix.h"
#include "vdi.h"
                    
#define VDI_REG_BLOCK   2LL
#define VDI_RADIX_ROOT  writable(3)
                                                            
#if 1
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* I haven't decided about this registry stuff, so this is just a really
 * quick lash-up so that there is some way to track VDIs.
 *
 * (Most vdi access should be with a direct handle to the block, so this
 *  registry is just for start-of-day lookup and other control operations.)
 */

vdi_registry_t *create_vdi_registry(void)
{
    vdi_registry_t *reg = (vdi_registry_t *)newblock();
    
    if (reg == NULL)
        return NULL;
    
    /* zero-fill the vdi radix root while we have an empty block. */
    writeblock(VDI_RADIX_ROOT, (void *)reg);
    
    
    DPRINTF("[vdi.c] Creating VDI registry!\n");
    reg->magic      = VDI_REG_MAGIC;
    reg->nr_vdis    = 0;
    
    writeblock(VDI_REG_BLOCK, (void *)reg);
    
    return reg;
}
    
vdi_registry_t *get_vdi_registry(void)
{
    vdi_registry_t *vdi_reg = (vdi_registry_t *)readblock(VDI_REG_BLOCK);
    
    if ( vdi_reg == NULL )
        vdi_reg = create_vdi_registry();
    
    if ( vdi_reg->magic != VDI_REG_MAGIC ) {
        freeblock(vdi_reg);
        return NULL;
    }
    
    return vdi_reg;
}

vdi_t *vdi_create(snap_id_t *parent_snap, char *name)
{
    int ret;
    vdi_t *vdi;
    vdi_registry_t *vdi_reg;
    snap_rec_t snap_rec;
    
    /* create a vdi struct */
    vdi = newblock();
    if (vdi == NULL) 
        return NULL;
    
    if ( snap_get_id(parent_snap, &snap_rec) == 0 ) {
        vdi->radix_root = snapshot(snap_rec.radix_root);
    } else {
        vdi->radix_root = allocblock((void *)vdi); /* vdi is just zeros here */
        vdi->radix_root = writable(vdi->radix_root); /* grr. */
    }
    
    /* create a snapshot log, and add it to the vdi struct */
    
    ret = snap_block_create(parent_snap, &vdi->snap);
    if ( ret != 0 ) {
        DPRINTF("Error getting snap block in vdi_create.\n");
        freeblock(vdi);
        return NULL;
    }
            
    /* append the vdi to the registry, fill block and id.             */
    /* implicit allocation means we have to write the vdi twice here. */
    vdi_reg    = get_vdi_registry();
    if ( vdi_reg == NULL ) {
        freeblock(vdi);
        return NULL;
    }
    
    vdi->block = allocblock((void *)vdi);
    vdi->id    = vdi_reg->nr_vdis++;
    strncpy(vdi->name, name, VDI_NAME_SZ);
    vdi->name[VDI_NAME_SZ] = '\0';
    writeblock(vdi->block, (void *)vdi);
    
    update(VDI_REG_HEIGHT, VDI_RADIX_ROOT, vdi->id, vdi->block);
    writeblock(VDI_REG_BLOCK, (void *)vdi_reg);
    freeblock(vdi_reg);
    
    return vdi;
}

vdi_t *vdi_get(u64 vdi_id)
{
    u64 vdi_blk;
    vdi_t *vdi;
    
    vdi_blk = lookup(VDI_REG_HEIGHT, VDI_RADIX_ROOT, vdi_id);
    
    if ( vdi_blk == 0 )
        return NULL;
    
    vdi = (vdi_t *)readblock(vdi_blk);
    return vdi;
}

u64 vdi_lookup_block(vdi_t *vdi, u64 vdi_block, int *writable)
{
    u64 gblock;
    
    gblock = lookup(VDI_HEIGHT, vdi->radix_root, vdi_block);
    
    if (writable != NULL) *writable = iswritable(gblock);

    return getid(gblock);
}

void vdi_update_block(vdi_t *vdi, u64 vdi_block, u64 g_block)
{
    u64 id;
    
    /* updates are always writable. */
    id = writable(g_block);
    
    vdi->radix_root = update(VDI_HEIGHT, vdi->radix_root, vdi_block, id);
    writeblock(vdi->block, vdi);
}

void vdi_snapshot(vdi_t *vdi)
{
    snap_rec_t rec;
    int ret;
    
    rec.radix_root = vdi->radix_root;
    gettimeofday(&rec.timestamp, NULL);
    rec.deleted = 0;
    
    vdi->radix_root = snapshot(vdi->radix_root);
    ret = snap_append(&vdi->snap, &rec, &vdi->snap);
    if ( ret != 0 ) {
        printf("snap_append returned failure\n");
        return;
    }
    writeblock(vdi->block, vdi);
}
    
int __init_vdi()
{
    /* force the registry to be created if it doesn't exist. */
    vdi_registry_t *vdi_reg = get_vdi_registry();
    if (vdi_reg == NULL) {
        printf("[vdi.c] Couldn't get/create a VDI registry!\n");
        return -1;
    }
    freeblock(vdi_reg);
    
    return 0;
}
    
#ifdef VDI_STANDALONE

#define TEST_VDIS      50
#define NR_ITERS    50000
#define FORK_POINTS   200
#define INIT_VDIS       3
#define INIT_SNAPS     40

/* These must be of decreasing size: */
#define NEW_FORK       (RAND_MAX-(RAND_MAX/1000))
#define NEW_ROOT_VDI   (RAND_MAX-((RAND_MAX/1000)*2))
#define NEW_FORK_VDI   (RAND_MAX-((RAND_MAX/1000)*3))

#define GRAPH_DOT_FILE "vdi.dot"
#define GRAPH_PS_FILE  "vdi.ps"


typedef struct sh_st {
    snap_id_t     id;
    struct sh_st *next;
} sh_t;

#define SNAP_HASHSZ 1024
sh_t *node_hash[SNAP_HASHSZ];
#define SNAP_HASH(_id) (((int)(_id)->block^(_id)->index)%SNAP_HASHSZ)

#define SNAPID_EQUAL(_a,_b) \
    (((_a)->block==(_b)->block) && ((_a)->index==(_b)->index))
int sh_check_and_add(snap_id_t *id)
{
    sh_t **s = &node_hash[SNAP_HASH(id)];
    
    while (*s != NULL) {
        if (SNAPID_EQUAL(&((*s)->id), id))
            return 1;
        *s = (*s)->next;
    }
    
    *s = (sh_t *)malloc(sizeof(sh_t));
    (*s)->id = *id;
    (*s)->next = NULL;
    
    return 0;
}

int main(int argc, char *argv[])
{
    vdi_t *vdi_list[TEST_VDIS];
    snap_id_t id, fork_points[FORK_POINTS];
    int nr_vdis = 0, nr_forks = 0;
    int i, j, r;
    FILE *f;
    char name[VDI_NAME_SZ];
    
    __init_blockstore();
    __init_vdi();
    
    printf("[o] Generating seed VDIs. (%d VDIs)\n", INIT_VDIS);
    
    for (i=0; i<INIT_VDIS; i++) {
        r=rand();
        
        sprintf(name, "VDI Number %d", nr_vdis);
        vdi_list[i] = vdi_create(NULL, name);
        for (j=0; j<(r%INIT_SNAPS); j++)
            vdi_snapshot(vdi_list[i]);
        fork_points[i] = vdi_list[i]->snap;
        nr_vdis++;
        nr_forks++;
    }
    
    printf("[o] Running a random workload. (%d iterations)\n", NR_ITERS);
            
    for (i=0; i<NR_ITERS; i++) {
        r = rand();
        
        if ( r > NEW_FORK ) {
            if ( nr_forks > FORK_POINTS )
                continue;
            id = vdi_list[r%nr_vdis]->snap;
            if ( ( id.block == 0 ) || ( id.index == 0 ) )
                continue;
            id.index--;
            fork_points[nr_forks++] = id;
            
        } else if ( r > NEW_ROOT_VDI ) {
            
            if ( nr_vdis == TEST_VDIS )
                continue;
            
            sprintf(name, "VDI Number %d.", nr_vdis);
            vdi_list[nr_vdis++] = vdi_create(NULL, name);
            
        } else if ( r > NEW_FORK_VDI ) {
            
            if ( nr_vdis == TEST_VDIS )
                continue;
            
            sprintf(name, "VDI Number %d.", nr_vdis);
            vdi_list[nr_vdis++] = vdi_create(&fork_points[r%nr_forks], name);
            
        } else /* SNAPSHOT */ {
            
            vdi_snapshot(vdi_list[r%nr_vdis]);
            
        }
    }
    
    /* now dump it out to a dot file. */
    printf("[o] Dumping state to a dot graph. (%d VDIs)\n", nr_vdis);
    
    f = fopen(GRAPH_DOT_FILE, "w");
    
    /* write graph preamble */
    fprintf(f, "digraph G {\n");
    fprintf(f, "   rankdir=LR\n");
    
    for (i=0; i<nr_vdis; i++) {
        char oldnode[255];
        snap_block_t *blk;
        snap_id_t id = vdi_list[i]->snap;
        int nr_snaps, done=0;
        
        /* add a node for the id */
printf("vdi: %d\n", i);
        fprintf(f, "   n%Ld%d [color=blue,shape=box,label=\"%s\\nb:%Ld\\nidx:%d\"]\n", 
                id.block, id.index, vdi_list[i]->name,
                id.block, id.index);
        sprintf(oldnode, "n%Ld%d", id.block, id.index);
        
        while (id.block != 0) {
            blk = snap_get_block(id.block);
            nr_snaps = blk->hdr.log_entries - (blk->hdr.nr_entries - id.index);
            id = blk->hdr.fork_block;
            
            done = sh_check_and_add(&id);
            
            /* add a node for the fork_id */
            if (!done) {
                fprintf(f, "   n%Ld%d [shape=box,label=\"b:%Ld\\nidx:%d\"]\n", 
                    id.block, id.index,
                    id.block, id.index);
            }
            
            /* add an edge between them */
            fprintf(f, "   n%Ld%d -> %s [label=\"%u snapshots\"]\n",
                    id.block, id.index, oldnode, nr_snaps);
            sprintf(oldnode, "n%Ld%d", id.block, id.index);
            freeblock(blk);
            
            if (done) break;
        }
    }
    
    /* write graph postamble */
    fprintf(f, "}\n");
    fclose(f);
    
    printf("[o] Generating postscript graph. (%s)\n", GRAPH_PS_FILE);
    {
        char cmd[255];
        sprintf(cmd, "dot %s -Tps -o %s", GRAPH_DOT_FILE, GRAPH_PS_FILE);
        system(cmd);
    }
    return 0;
}

#endif
