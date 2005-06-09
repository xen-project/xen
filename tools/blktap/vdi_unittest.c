/**************************************************************************
 * 
 * vdi_unittest.c
 *
 * Run a small test workload to ensure that data access through a vdi
 * is (at least superficially) correct.
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "requests-async.h"
#include "blockstore.h"
#include "radix.h"
#include "vdi.h"

#define TEST_PAGES  32
static char *zero_page;
static char pages[TEST_PAGES][BLOCK_SIZE];
static int next_page = 0;

void fill_test_pages(void)
{
    int i, j;
    long *page;

    for (i=0; i< TEST_PAGES; i++) {
        page = (unsigned long *)pages[i];
        for (j=0; j<(BLOCK_SIZE/4); j++) {
            page[j] = random();
        }
    }

    zero_page = newblock();
}

inline u64 make_vaddr(u64 L1, u64 L2, u64 L3)
{
    u64 ret = L1;

    ret = (ret << 9) | L2;
    ret = (ret << 9) | L3;

    return ret;
}

void touch_block(vdi_t *vdi, u64 L1, u64 L2, u64 L3)
{
    u64 vaddr;
    char *page = pages[next_page++];
    char *rpage = NULL;

    printf("TOUCH (%3Lu, %3Lu, %3Lu)\n", L1, L2, L3);

    vaddr = make_vaddr(L1, L2, L3);
    vdi_write_s(vdi, vaddr, page);
    rpage = vdi_read_s(vdi, vaddr);

    if (rpage == NULL) 
    {
        printf( "read %Lu returned NULL\n", vaddr); 
        return; 
    }

    if (memcmp(page, rpage, BLOCK_SIZE) != 0)
    {
        printf( "read %Lu returned a different page\n", vaddr);
        return;
    }

    freeblock(rpage);
}

void test_block(vdi_t *vdi, u64 L1, u64 L2, u64 L3, char *page)
{
    u64 vaddr;
    char *rpage = NULL;

    printf("TEST  (%3Lu, %3Lu, %3Lu)\n", L1, L2, L3);

    vaddr = make_vaddr(L1, L2, L3);
    rpage = vdi_read_s(vdi, vaddr);

    if (rpage == NULL) 
    {
        printf( "read %Lu returned NULL\n", vaddr); 
        return; 
    }

    if (memcmp(page, rpage, BLOCK_SIZE) != 0)
    {
        printf( "read %Lu returned a different page\n", vaddr);
        return;
    }

    freeblock(rpage);
}

void coverage_test(vdi_t *vdi)
{
    u64 vaddr;
    int i, j, k;

    /* Do a series of writes and reads to test all paths through the 
     * async radix code.  The radix request code will dump CRC warnings
     * if there are data problems here as well.
     */

    /* L1 Zero */
    touch_block(vdi, 0, 0, 0);

    /* L2 Zero */
    i = next_page;
    touch_block(vdi, 0, 1, 0);

    /* L3 Zero */
    j = next_page;
    touch_block(vdi, 0, 0, 1);
    k = next_page;
    touch_block(vdi, 0, 1, 1);

    /* Direct write */
    touch_block(vdi, 0, 0, 0);

    vdi_snapshot(vdi);

    /* L1 fault */
    touch_block(vdi, 0, 0, 0);
    /* test the read-only branches that should have been copied over. */
    test_block(vdi, 0, 1, 0, pages[i]);
    test_block(vdi, 0, 0, 1, pages[j]);

    /* L2 fault */
    touch_block(vdi, 0, 1, 0);
    test_block(vdi, 0, 1, 1, pages[k]);

    /* L3 fault */
    touch_block(vdi, 0, 0, 1);
    
    /* read - L1 zero */
    test_block(vdi, 1, 0, 0, zero_page);
    
    /* read - L2 zero */
    test_block(vdi, 0, 2, 0, zero_page);

    /* read - L3 zero */
    test_block(vdi, 0, 0, 2, zero_page);
}

int main(int argc, char *argv[])
{
    vdi_t       *vdi;
    u64          id;
    int          fd;
    struct stat  st;
    u64          tot_size;
    char         spage[BLOCK_SIZE];
    char        *dpage;
    u64          vblock = 0, count=0;
    
    __init_blockstore();
    init_block_async();
    __init_vdi();
        
    vdi = vdi_create( NULL, "UNIT TEST VDI");
    
    if ( vdi == NULL ) {
        printf("Failed to create VDI!\n");
        freeblock(vdi);
        exit(-1);
    }

    fill_test_pages();
    coverage_test(vdi);
    
    freeblock(vdi);
    
    return (0);
}
