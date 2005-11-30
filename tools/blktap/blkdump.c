/* blkdump.c
 *
 * show a running trace of block requests as they fly by.
 * 
 * (c) 2004 Andrew Warfield.
 */
 
#include <stdio.h>
#include "blktaplib.h"
 
int request_print(blkif_request_t *req)
{
    int i;
    
    if ( (req->operation == BLKIF_OP_READ) ||
         (req->operation == BLKIF_OP_WRITE) )
    {
        printf("[%2u:%2u<%5s] (nr_segs: %03u, dev: %03u, %010llu)\n", 
                ID_TO_DOM(req->id), ID_TO_IDX(req->id), 
                blkif_op_name[req->operation], 
                req->nr_segments, req->handle, 
                req->sector_number);
        
        
        for (i=0; i < req->nr_segments; i++) {
            printf("              (gref: 0x%8x start: %u stop: %u)\n",
                   req->seg[i].gref,
                   req->seg[i].first_sect,
                   req->seg[i].last_sect);
        }
            
    } else {
        printf("Unknown request message type.\n");
    }
    
    return BLKTAP_PASS;
}

int response_print(blkif_response_t *rsp)
{   
    if ( (rsp->operation == BLKIF_OP_READ) ||
         (rsp->operation == BLKIF_OP_WRITE) )
    {
        printf("[%2u:%2u>%5s] (status: %d)\n", 
                ID_TO_DOM(rsp->id), ID_TO_IDX(rsp->id), 
                blkif_op_name[rsp->operation], 
                rsp->status);
            
    } else {
        printf("Unknown request message type.\n");
    }
    return BLKTAP_PASS;
}

int main(int argc, char *argv[])
{
    blktap_register_request_hook("request_print", request_print);
    blktap_register_response_hook("response_print", response_print);
    blktap_listen();
    
    return 0;
}
