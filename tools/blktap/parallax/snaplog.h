/**************************************************************************
 * 
 * snaplog.h
 *
 * Snapshot log on-disk data structure.
 *
 */
 
#include "radix.h"
#include "blockstore.h"    /* for BLOCK_SIZE */
 
#ifndef __SNAPLOG_H__
#define __SNAPLOG_H__

typedef struct snap_id {
    u64            block;
    unsigned int   index;
} snap_id_t;

typedef struct snap_rec {
    u64            radix_root;
    struct timeval timestamp;
    /* flags: */
    unsigned       deleted:1;
} snap_rec_t;


int  snap_block_create(snap_id_t *parent_id, snap_id_t *new_id);
int  snap_append(snap_id_t *id, snap_rec_t *rec, snap_id_t *new_id);
int  snap_collapse(int height, snap_id_t *p_id, snap_id_t *c_id);
void snap_print_history(snap_id_t *snap_id);
int  snap_get_id(snap_id_t *id, snap_rec_t *target);


/* exported for vdi debugging */
#define SNAP_MAGIC 0xff00ff0aa0ff00ffLL

static const snap_id_t null_snap_id = { 0, 0 }; 

typedef struct snap_block_hdr {
    u64            magic;
    snap_id_t      parent_block; /* parent block within this chain */
    snap_id_t      fork_block;   /* where this log was forked */
    unsigned       log_entries;  /* total entries since forking */
    unsigned short nr_entries;   /* entries in snaps[] */
    unsigned short immutable;    /* has this snap page become immutable? */
} snap_block_hdr_t;


#define SNAPS_PER_BLOCK \
    ((BLOCK_SIZE - sizeof(snap_block_hdr_t)) / sizeof(snap_rec_t))

typedef struct snap_block {
    snap_block_hdr_t hdr;
    snap_rec_t       snaps[SNAPS_PER_BLOCK];
} snap_block_t;
    

snap_block_t *snap_get_block(u64 block);

#endif /* __SNAPLOG_H__ */
