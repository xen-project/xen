/*
 * Radix tree for mapping (up to) 63-bit virtual block IDs to
 * 63-bit global block IDs
 *
 * Pointers within the tree set aside the least significant bit to indicate
 * whther or not the target block is writable from this node.
 *
 * The block with ID 0 is assumed to be an empty block of all zeros
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "blockstore.h"
#include "radix.h"

#define RADIX_TREE_MAP_SHIFT 9
#define RADIX_TREE_MAP_MASK 0x1ff
#define RADIX_TREE_MAP_ENTRIES 512

/*
#define DEBUG
*/

#define ZERO 0LL
#define ONE 1LL
#define ONEMASK 0xffffffffffffffeLL


typedef u64 *radix_tree_node;

/*
 * block device interface and other helper functions
 * with these functions, block id is just a 63-bit number, with
 * no special consideration for the LSB
 */
radix_tree_node cloneblock(radix_tree_node block);

/*
 * main api
 * with these functions, the LSB of root always indicates
 * whether or not the block is writable, including the return
 * values of update and snapshot
 */
u64 lookup(int height, u64 root, u64 key);
u64 update(int height, u64 root, u64 key, u64 val);
u64 snapshot(u64 root);

/**
 * cloneblock: clone an existing block in memory
 *   @block: the old block
 *
 *   @return: new block, with LSB cleared for every entry
 */
radix_tree_node cloneblock(radix_tree_node block) {
    radix_tree_node node = (radix_tree_node) malloc(BLOCK_SIZE);
    int i;
    if (node == NULL) {
        perror("cloneblock malloc");
        return NULL;
    }
    for (i = 0; i < RADIX_TREE_MAP_ENTRIES; i++)
        node[i] = block[i] & ONEMASK;
    return node;
}

/**
 * lookup: find a value given a key
 *   @height: height in bits of the radix tree
 *   @root: root node id, with set LSB indicating writable node
 *   @key: key to lookup
 *
 *   @return: value on success, zero on error
 */
u64 lookup(int height, u64 root, u64 key) {
    radix_tree_node node;
    
    assert(key >> height == 0);

    /* the root block may be smaller to ensure all leaves are full */
    height = ((height - 1) / RADIX_TREE_MAP_SHIFT) * RADIX_TREE_MAP_SHIFT;

    /* now carve off equal sized chunks at each step */
    for (;;) {
        u64 oldroot;

#ifdef DEBUG
        printf("lookup: height=%3d root=%3Ld offset=%3d%s\n", height, root,
                (int) ((key >> height) & RADIX_TREE_MAP_MASK),
                (iswritable(root) ? "" : " (readonly)"));
#endif
        
        if (getid(root) == ZERO)
            return ZERO;

        oldroot = root;
        node = (radix_tree_node) readblock(getid(root));
        if (node == NULL)
            return ZERO;

        root = node[(key >> height) & RADIX_TREE_MAP_MASK];
        freeblock(node);

        if (height == 0)
            return root;

        height -= RADIX_TREE_MAP_SHIFT;
    }

    return ZERO;
}

/*
 * update: set a radix tree entry, doing copy-on-write as necessary
 *   @height: height in bits of the radix tree
 *   @root: root node id, with set LSB indicating writable node
 *   @key: key to set
 *   @val: value to set, s.t. radix(key)=val
 *
 *   @returns: (possibly new) root id on success (with LSB=1), 0 on failure
 */
u64 update(int height, u64 root, u64 key, u64 val) {
    int offset;
    u64 child;
    radix_tree_node node;
    
    /* base case--return val */
    if (height == 0)
        return val;

    /* the root block may be smaller to ensure all leaves are full */
    height = ((height - 1) / RADIX_TREE_MAP_SHIFT) * RADIX_TREE_MAP_SHIFT;
    offset = (key >> height) & RADIX_TREE_MAP_MASK;

#ifdef DEBUG
    printf("update: height=%3d root=%3Ld offset=%3d%s\n", height, root,
            offset, (iswritable(root)?"":" (clone)"));
#endif

    /* load a block, or create a new one */
    if (root == ZERO) {
        node = (radix_tree_node) newblock();
    } else {
        node = (radix_tree_node) readblock(getid(root));

        if (!iswritable(root)) {
            /* need to clone this node */
            radix_tree_node oldnode = node;
            node = cloneblock(node);
            freeblock(oldnode);
            root = ZERO;
        }
    }

    if (node == NULL) {
#ifdef DEBUG
        printf("update: node is null!\n");
#endif
        return ZERO;
    }

    child = update(height, node[offset], key, val);

    if (child == ZERO) {
        freeblock(node);
        return ZERO;
    } else if (child == node[offset]) {
        /* no change, so we already owned the child */
        assert(iswritable(root));

        freeblock(node);
        return root;
    }

    node[offset] = child;

    /* new/cloned blocks need to be saved */
    if (root == ZERO) {
        /* mark this as an owned block */
        root = allocblock(node);
        if (root)
            root = writable(root);
    } else if (writeblock(getid(root), node) < 0) {
        freeblock(node);
        return ZERO;
    }

    freeblock(node);
    return root;
}

/**
 * snapshot: create a snapshot
 *   @root: old root node
 *
 *   @return: new root node, 0 on error
 */
u64 snapshot(u64 root) {
    radix_tree_node node, newnode;

    if ((node = readblock(getid(root))) == NULL)
        return ZERO;

    newnode = cloneblock(node);
    freeblock(node);
    if (newnode == NULL)
        return ZERO;
    
    root = allocblock(newnode);
    freeblock(newnode);

    if (root == ZERO)
        return ZERO;
    else
        return writable(root);
}

void print_root(u64 root, int height, u64 val, FILE *dot_f)
{
    FILE *f;
    int i;
    radix_tree_node node;
    char *style[2] = { "", "style=bold,color=blue," };
    
    if (dot_f == NULL) {
        f = fopen("radix.dot", "w");
        if (f == NULL) {
            perror("print_root: open");
            return;
        }

        /* write graph preamble */
        fprintf(f, "digraph G {\n");

        /* add a node for this root. */
        fprintf(f, "   n%Ld [%sshape=box,label=\"%Ld\"];\n", 
                getid(root), style[iswritable(root)], getid(root));
    }
    
    /* base case--return val */
    if (height == 0) {
        /* add a node and edge for each child root */
        node = (radix_tree_node) readblock(getid(root));
        if (node == NULL)
            return;
        
        for (i = 0; i < RADIX_TREE_MAP_ENTRIES; i++) {
            if (node[i] != 0) {
                fprintf(f, "   n%Ld [%sshape=box,label=\"%Ld\"];\n", 
                        getid(node[i]), style[iswritable(node[i])], 
                        getid(node[i]));
                fprintf(f, "   n%Ld -> n%Ld [label=\"%d\"]\n", getid(root), 
                        getid(node[i]), i);
            }
        }
        return;
    }

    /* the root block may be smaller to ensure all leaves are full */
    height = ((height - 1) / RADIX_TREE_MAP_SHIFT) * RADIX_TREE_MAP_SHIFT;

    if (getid(root) == ZERO)
        return;

    node = (radix_tree_node) readblock(getid(root));
    if (node == NULL)
        return;

    /* add a node and edge for each child root */
    for (i = 0; i < RADIX_TREE_MAP_ENTRIES; i++)
        if (node[i] != 0) {
            fprintf(f, "   n%Ld [%sshape=box,label=\"%Ld\"];\n", 
                    getid(node[i]), style[iswritable(node[i])], 
                    getid(node[i]));
            print_root(node[i], height-RADIX_TREE_MAP_SHIFT, 
                    val + (((u64)i)<<height), f);
            fprintf(f, "   n%Ld -> n%Ld [label=\"%d\"]\n", getid(root), 
                    getid(node[i]), i);
        }
        
        /*
        
        root = node[(key >> height) & RADIX_TREE_MAP_MASK];
        freeblock(state, getid(oldroot), node);

        if (height == 0)
            return root;

        height -= RADIX_TREE_MAP_SHIFT;
        */
    //}

    
    /* write graph postamble */
    if (dot_f == NULL) {
        fprintf(f, "}\n");
        fclose(f);
    }
}

#ifdef RADIX_STANDALONE

int main(int argc, char **argv) {
    u64 key = ZERO, val = ZERO;
    u64 root = writable(ONE);
    char buff[4096];

    __init_blockstore();
    
    memset(buff, 0, 4096);
    /*fp = open("radix.dat", O_RDWR | O_CREAT, 0644);

    if (fp < 3) {
        perror("open");
        return -1;
    }
    if (lseek(fp, 0, SEEK_END) == 0) {
        write(fp, buff, 4096);
    }*/
           
    printf("Recognized commands:\n"
           "Note: the LSB of a node number indicates if it is writable\n"
           "  root <node>               set root to <node>\n"
           "  snapshot                  take a snapshot of the root\n"
           "  set <key> <val>           set key=val\n"
           "  get <key>                 query key\n"
           "  quit\n"
           "\nroot = %Ld\n", root);
    for (;;) {
        print_root(root, 34, 0, NULL);
        system("dot radix.dot -Tps -o radix.ps");

        printf("> ");
        fflush(stdout);
        fgets(buff, 1024, stdin);
        if (feof(stdin))
            break;
        if (sscanf(buff, " root %Ld", &root) == 1) {
            printf("root set to %Ld\n", root);
        } else if (sscanf(buff, " set %Ld %Ld", &key, &val) == 2) {
            root = update(34, root, key, val);
            printf("root = %Ld\n", root);
        } else if (sscanf(buff, " get %Ld", &key) == 1) {
            val = lookup(34, root, key, NULL);
            printf("value = %Ld\n", val);
        } else if (!strcmp(buff, "quit\n")) {
            break;
        } else if (!strcmp(buff, "snapshot\n")) {
            root = snapshot(root);
            printf("new root = %Ld\n", root);
        } else if (sscanf(buff, " pr %Ld", &root) == 1) {
            print_root(root, 34, 0, NULL);
        } else {
            printf("command not recognized\n");
        }
    }
    return 0;
}

#endif
