/* blkcowlib.h
 *
 * copy on write a block device.  in a really inefficient way.
 * 
 * (c) 2004 Andrew Warfield.
 *
 * public interfaces to the CoW tap.
 *
 */
 
int  cow_control  (control_msg_t *msg);
int  cow_request  (blkif_request_t *req);
int  cow_response (blkif_response_t *rsp);
void cow_init     (void);
