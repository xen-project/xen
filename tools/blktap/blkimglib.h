/* blkimglib.h
 *
 * file image-backed block device.
 * 
 * (c) 2004 Andrew Warfield.
 *
 * Xend has been modified to use an amorfs:[fsid] disk tag.
 * This will show up as device type (maj:240,min:0) = 61440.
 *
 * The fsid is placed in the sec_start field of the disk extent.
 */

int image_control(control_msg_t *msg);
int image_request(blkif_request_t *req);
int image_response(blkif_response_t *rsp); /* noop */
void image_init(void);
