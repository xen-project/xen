/* blkdump.c
 *
 * show a running trace of block requests as they fly by.
 * 
 * (c) 2004 Andrew Warfield.
 */
 
#include <stdio.h>
#include "blktaplib.h"
 
int control_print(control_msg_t *msg)
{
    if (msg->type != CMSG_BLKIF_BE) 
    {
        printf("***\nUNEXPECTED CTRL MSG MAJOR TYPE(%d)\n***\n", msg->type);
        return 0;
    }
    
    switch(msg->subtype)
    {
    case CMSG_BLKIF_BE_CREATE:
        if ( msg->length != sizeof(blkif_be_create_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_CREATE(d:%d,h:%d)\n",
                ((blkif_be_create_t *)msg->msg)->domid,
                ((blkif_be_create_t *)msg->msg)->blkif_handle);
        break; 
    case CMSG_BLKIF_BE_DESTROY:
        if ( msg->length != sizeof(blkif_be_destroy_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_DESTROY(d:%d,h:%d)\n",
                ((blkif_be_destroy_t *)msg->msg)->domid,
                ((blkif_be_destroy_t *)msg->msg)->blkif_handle);
        break;   
    case CMSG_BLKIF_BE_CONNECT:
        if ( msg->length != sizeof(blkif_be_connect_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_CONNECT(d:%d,h:%d)\n",
                ((blkif_be_connect_t *)msg->msg)->domid,
                ((blkif_be_connect_t *)msg->msg)->blkif_handle);
        break;        
    case CMSG_BLKIF_BE_DISCONNECT:
        if ( msg->length != sizeof(blkif_be_disconnect_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_DISCONNECT(d:%d,h:%d)\n",
                ((blkif_be_disconnect_t *)msg->msg)->domid,
                ((blkif_be_disconnect_t *)msg->msg)->blkif_handle);
        break;     
    case CMSG_BLKIF_BE_VBD_CREATE:
        if ( msg->length != sizeof(blkif_be_vbd_create_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_VBD_CREATE(d:%d,h:%d,v:%d)\n",
                ((blkif_be_vbd_create_t *)msg->msg)->domid,
                ((blkif_be_vbd_create_t *)msg->msg)->blkif_handle,
                ((blkif_be_vbd_create_t *)msg->msg)->vdevice);
        break;
    case CMSG_BLKIF_BE_VBD_DESTROY:
        if ( msg->length != sizeof(blkif_be_vbd_destroy_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_VBD_DESTROY(d:%d,h:%d,v:%d)\n",
                ((blkif_be_vbd_destroy_t *)msg->msg)->domid,
                ((blkif_be_vbd_destroy_t *)msg->msg)->blkif_handle,
                ((blkif_be_vbd_destroy_t *)msg->msg)->vdevice);
        break;
    case CMSG_BLKIF_BE_VBD_GROW:
        if ( msg->length != sizeof(blkif_be_vbd_grow_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_VBD_GROW(d:%d,h:%d,v:%d)\n",
                ((blkif_be_vbd_grow_t *)msg->msg)->domid,
                ((blkif_be_vbd_grow_t *)msg->msg)->blkif_handle,
                ((blkif_be_vbd_grow_t *)msg->msg)->vdevice);
        printf("              Extent: sec_start: %llu sec_len: %llu, dev: %d\n",
                ((blkif_be_vbd_grow_t *)msg->msg)->extent.sector_start,
                ((blkif_be_vbd_grow_t *)msg->msg)->extent.sector_length,
                ((blkif_be_vbd_grow_t *)msg->msg)->extent.device);
        break;
    case CMSG_BLKIF_BE_VBD_SHRINK:
        if ( msg->length != sizeof(blkif_be_vbd_shrink_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_VBD_SHRINK(d:%d,h:%d,v:%d)\n",
                ((blkif_be_vbd_shrink_t *)msg->msg)->domid,
                ((blkif_be_vbd_shrink_t *)msg->msg)->blkif_handle,
                ((blkif_be_vbd_shrink_t *)msg->msg)->vdevice);
        break;
    default:
        goto parse_error;
    }
   
    return 0; 
      
parse_error:
    printf("[CONTROL_MSG] Bad message type or length!\n");
    return 0;
}
 
int request_print(blkif_request_t *req)
{
    int i;
    unsigned long fas;
    
    if ( req->operation == BLKIF_OP_PROBE ) {
        printf("[%2u:%2u<%s]\n", ID_TO_DOM(req->id), ID_TO_IDX(req->id),
                blkif_op_name[req->operation]);
        return BLKTAP_PASS;
    } else {
        printf("[%2u:%2u<%5s] (nr_segs: %03u, dev: %03u, %010llu)\n", 
                ID_TO_DOM(req->id), ID_TO_IDX(req->id), 
                blkif_op_name[req->operation], 
                req->nr_segments, req->device, 
                req->sector_number);
        
        
        for (i=0; i < req->nr_segments; i++) {
            fas = req->frame_and_sects[i];
            printf("              (pf: 0x%8lx start: %lu stop: %lu)\n",
                    (fas & PAGE_MASK),
                    blkif_first_sect(fas),
                    blkif_last_sect(fas)
                    );
        }
            
    }
    
    return BLKTAP_PASS;
}

int response_print(blkif_response_t *rsp)
{   
    if ( rsp->operation == BLKIF_OP_PROBE ) {
        printf("[%2u:%2u>%s]\n", ID_TO_DOM(rsp->id), ID_TO_IDX(rsp->id),
                blkif_op_name[rsp->operation]);
        return BLKTAP_PASS;
    } else {
        printf("[%2u:%2u>%5s] (status: %d)\n", 
                ID_TO_DOM(rsp->id), ID_TO_IDX(rsp->id), 
                blkif_op_name[rsp->operation], 
                rsp->status);
            
    }
    return BLKTAP_PASS;
}

int main(int argc, char *argv[])
{
    blktap_register_ctrl_hook("control_print", control_print);
    blktap_register_request_hook("request_print", request_print);
    blktap_register_response_hook("response_print", response_print);
    blktap_listen();
    
    return 0;
}
