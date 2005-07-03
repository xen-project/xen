/**************************************************************************
 * 
 * vdi_tree.c
 *
 * Output current vdi tree to dot and postscript.
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "blockstore.h"
#include "radix.h"
#include "vdi.h"

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
    FILE *f;
    char dot_file[255] = GRAPH_DOT_FILE;
    char  ps_file[255] = GRAPH_PS_FILE;
    int nr_vdis = 0, nr_forks = 0;
    vdi_registry_t *reg;
    vdi_t *vdi;
    int i;
    
    __init_blockstore();
    __init_vdi();
    
    reg = get_vdi_registry();
    
    if ( reg == NULL ) {
        printf("couldn't get VDI registry.\n");
        exit(-1);
    }
    
    if ( argc > 1 ) {
        strncpy(ps_file, argv[1], 255);
        ps_file[255] = '\0';
    }
    
    /* now dump it out to a dot file. */
    printf("[o] Dumping state to a dot graph. (%d VDIs)\n", nr_vdis);
    
    f = fopen(dot_file, "w");
    
    /* write graph preamble */
    fprintf(f, "digraph G {\n");
    fprintf(f, "   rankdir=LR\n");
    
    for (i=0; i<reg->nr_vdis; i++) {
        char oldnode[255];
        snap_block_t *blk;
        snap_id_t id;
        int nr_snaps, done=0;
        
        vdi = vdi_get(i);
        id = vdi->snap;
        /* add a node for the id */
printf("vdi: %d\n", i);
        fprintf(f, "   n%Ld%d [color=blue,shape=box,label=\"%s\\nb:%Ld\\nidx:%d\"]\n", 
                id.block, id.index, vdi->name,
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
        sprintf(cmd, "dot %s -Tps -o %s", dot_file, ps_file);
        system(cmd);
    }
    return 0;
}
