#undef NDEBUG
#include <stdio.h>
#include <aio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <xenctrl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <unistd.h>
#include "fs-backend.h"

/* For debugging only */
#include <sys/time.h>
#include <time.h>


#define BUFFER_SIZE 1024


unsigned short get_request(struct mount *mount, struct fsif_request *req)
{
    unsigned short id = get_id_from_freelist(mount->freelist); 

    printf("Private Request id: %d\n", id);
    memcpy(&mount->requests[id].req_shadow, req, sizeof(struct fsif_request));
    mount->requests[id].active = 1;

    return id;
}


void dispatch_file_open(struct mount *mount, struct fsif_request *req)
{
    char *file_name, full_path[BUFFER_SIZE];
    int fd;
    struct timeval tv1, tv2;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    printf("Dispatching file open operation (gref=%d).\n", req->u.fopen.gref);
    /* Read the request, and open file */
    file_name = xc_gnttab_map_grant_ref(mount->gnth,
                                        mount->dom_id,
                                        req->u.fopen.gref,
                                        PROT_READ);
   
    req_id = req->id;
    printf("File open issued for %s\n", file_name); 
    assert(BUFFER_SIZE > 
           strlen(file_name) + strlen(mount->export->export_path) + 1); 
    sprintf(full_path, "%s/%s", mount->export->export_path, file_name);
    assert(xc_gnttab_munmap(mount->gnth, file_name, 1) == 0);
    printf("Issuing open for %s\n", full_path);
    fd = open(full_path, O_RDWR);
    printf("Got FD: %d\n", fd);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)fd;
}

void dispatch_file_close(struct mount *mount, struct fsif_request *req)
{
    int ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    printf("Dispatching file close operation (fd=%d).\n", req->u.fclose.fd);
   
    req_id = req->id;
    ret = close(req->u.fclose.fd);
    printf("Got ret: %d\n", ret);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}
void dispatch_file_read(struct mount *mount, struct fsif_request *req)
{
    void *buf;
    int fd;
    uint16_t req_id;
    unsigned short priv_id;
    struct fs_request *priv_req;

    /* Read the request */
    buf = xc_gnttab_map_grant_ref(mount->gnth,
                                  mount->dom_id,
                                  req->u.fread.gref,
                                  PROT_WRITE);
   
    req_id = req->id;
    printf("File read issued for FD=%d (len=%"PRIu64", offest=%"PRIu64")\n", 
            req->u.fread.fd, req->u.fread.len, req->u.fread.offset); 
   
    priv_id = get_request(mount, req);
    printf("Private id is: %d\n", priv_id);
    priv_req = &mount->requests[priv_id];
    priv_req->page = buf;

    /* Dispatch AIO read request */
    bzero(&priv_req->aiocb, sizeof(struct aiocb));
    priv_req->aiocb.aio_fildes = req->u.fread.fd;
    priv_req->aiocb.aio_nbytes = req->u.fread.len;
    priv_req->aiocb.aio_offset = req->u.fread.offset;
    priv_req->aiocb.aio_buf = buf;
    assert(aio_read(&priv_req->aiocb) >= 0);

     
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
}

void end_file_read(struct mount *mount, struct fs_request *priv_req)
{
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    /* Release the grant */
    assert(xc_gnttab_munmap(mount->gnth, priv_req->page, 1) == 0);

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    req_id = priv_req->req_shadow.id; 
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)aio_return(&priv_req->aiocb);
}

void dispatch_file_write(struct mount *mount, struct fsif_request *req)
{
    void *buf;
    int fd;
    uint16_t req_id;
    unsigned short priv_id;
    struct fs_request *priv_req;

    /* Read the request */
    buf = xc_gnttab_map_grant_ref(mount->gnth,
                                  mount->dom_id,
                                  req->u.fwrite.gref,
                                  PROT_READ);
   
    req_id = req->id;
    printf("File write issued for FD=%d (len=%"PRIu64", offest=%"PRIu64")\n", 
            req->u.fwrite.fd, req->u.fwrite.len, req->u.fwrite.offset); 
   
    priv_id = get_request(mount, req);
    printf("Private id is: %d\n", priv_id);
    priv_req = &mount->requests[priv_id];
    priv_req->page = buf;

    /* Dispatch AIO write request */
    bzero(&priv_req->aiocb, sizeof(struct aiocb));
    priv_req->aiocb.aio_fildes = req->u.fwrite.fd;
    priv_req->aiocb.aio_nbytes = req->u.fwrite.len;
    priv_req->aiocb.aio_offset = req->u.fwrite.offset;
    priv_req->aiocb.aio_buf = buf;
    assert(aio_write(&priv_req->aiocb) >= 0);

     
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
}

void end_file_write(struct mount *mount, struct fs_request *priv_req)
{
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    /* Release the grant */
    assert(xc_gnttab_munmap(mount->gnth, priv_req->page, 1) == 0);
    
    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    req_id = priv_req->req_shadow.id; 
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)aio_return(&priv_req->aiocb);
}

void dispatch_stat(struct mount *mount, struct fsif_request *req)
{
    struct fsif_stat_response *buf;
    struct stat stat;
    int fd, ret;
    uint16_t req_id;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;

    /* Read the request */
    buf = xc_gnttab_map_grant_ref(mount->gnth,
                                  mount->dom_id,
                                  req->u.fstat.gref,
                                  PROT_WRITE);
   
    req_id = req->id;
    fd = req->u.fstat.fd;
    printf("File stat issued for FD=%d\n", fd); 
   
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
   
    /* Stat, and create the response */ 
    ret = fstat(fd, &stat);
    printf("Mode=%o, uid=%d, a_time=%ld\n",
            stat.st_mode, stat.st_uid, stat.st_atime);
    buf->stat_mode  = stat.st_mode;
    buf->stat_uid   = stat.st_uid;
    buf->stat_gid   = stat.st_gid;
#ifdef BLKGETSIZE
    if (S_ISBLK(stat.st_mode)) {
	int sectors;
	if (ioctl(fd, BLKGETSIZE, &sectors)) {
	    perror("getting device size\n");
	    buf->stat_size = 0;
	} else
	    buf->stat_size = sectors << 9;
    } else
#endif
	buf->stat_size  = stat.st_size;
    buf->stat_atime = stat.st_atime;
    buf->stat_mtime = stat.st_mtime;
    buf->stat_ctime = stat.st_ctime;

    /* Release the grant */
    assert(xc_gnttab_munmap(mount->gnth, buf, 1) == 0);
    
    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}


void dispatch_truncate(struct mount *mount, struct fsif_request *req)
{
    int fd, ret;
    uint16_t req_id;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    int64_t length;

    req_id = req->id;
    fd = req->u.ftruncate.fd;
    length = req->u.ftruncate.length;
    printf("File truncate issued for FD=%d, length=%"PRId64"\n", fd, length); 
   
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
   
    /* Stat, and create the response */ 
    ret = ftruncate(fd, length);

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}

void dispatch_remove(struct mount *mount, struct fsif_request *req)
{
    char *file_name, full_path[BUFFER_SIZE];
    int ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    printf("Dispatching remove operation (gref=%d).\n", req->u.fremove.gref);
    /* Read the request, and open file */
    file_name = xc_gnttab_map_grant_ref(mount->gnth,
                                        mount->dom_id,
                                        req->u.fremove.gref,
                                        PROT_READ);
   
    req_id = req->id;
    printf("File remove issued for %s\n", file_name); 
    assert(BUFFER_SIZE > 
           strlen(file_name) + strlen(mount->export->export_path) + 1); 
    sprintf(full_path, "%s/%s", mount->export->export_path, file_name);
    assert(xc_gnttab_munmap(mount->gnth, file_name, 1) == 0);
    printf("Issuing remove for %s\n", full_path);
    ret = remove(full_path);
    printf("Got ret: %d\n", ret);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}


void dispatch_rename(struct mount *mount, struct fsif_request *req)
{
    char *buf, *old_file_name, *new_file_name;
    char old_full_path[BUFFER_SIZE], new_full_path[BUFFER_SIZE];
    int ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    printf("Dispatching rename operation (gref=%d).\n", req->u.fremove.gref);
    /* Read the request, and open file */
    buf = xc_gnttab_map_grant_ref(mount->gnth,
                                  mount->dom_id,
                                  req->u.frename.gref,
                                  PROT_READ);
   
    req_id = req->id;
    old_file_name = buf + req->u.frename.old_name_offset;
    new_file_name = buf + req->u.frename.new_name_offset;
    printf("File rename issued for %s -> %s (buf=%s)\n", 
            old_file_name, new_file_name, buf); 
    assert(BUFFER_SIZE > 
           strlen(old_file_name) + strlen(mount->export->export_path) + 1); 
    assert(BUFFER_SIZE > 
           strlen(new_file_name) + strlen(mount->export->export_path) + 1); 
    sprintf(old_full_path, "%s/%s", mount->export->export_path, old_file_name);
    sprintf(new_full_path, "%s/%s", mount->export->export_path, new_file_name);
    assert(xc_gnttab_munmap(mount->gnth, buf, 1) == 0);
    printf("Issuing rename for %s -> %s\n", old_full_path, new_full_path);
    ret = rename(old_full_path, new_full_path);
    printf("Got ret: %d\n", ret);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}


void dispatch_create(struct mount *mount, struct fsif_request *req)
{
    char *file_name, full_path[BUFFER_SIZE];
    int ret;
    int8_t directory;
    int32_t mode;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    printf("Dispatching file create operation (gref=%d).\n", req->u.fcreate.gref);
    /* Read the request, and create file/directory */
    mode = req->u.fcreate.mode;
    directory = req->u.fcreate.directory;
    file_name = xc_gnttab_map_grant_ref(mount->gnth,
                                        mount->dom_id,
                                        req->u.fcreate.gref,
                                        PROT_READ);
   
    req_id = req->id;
    printf("File create issued for %s\n", file_name); 
    assert(BUFFER_SIZE > 
           strlen(file_name) + strlen(mount->export->export_path) + 1); 
    sprintf(full_path, "%s/%s", mount->export->export_path, file_name);
    assert(xc_gnttab_munmap(mount->gnth, file_name, 1) == 0);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;

    if(directory)
    {
        printf("Issuing create for directory: %s\n", full_path);
        ret = mkdir(full_path, mode);
    }
    else
    {
        printf("Issuing create for file: %s\n", full_path);
        ret = creat(full_path, mode); 
    }
    printf("Got ret %d (errno=%d)\n", ret, errno);

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}

void dispatch_list(struct mount *mount, struct fsif_request *req)
{
    char *file_name, *buf, full_path[BUFFER_SIZE];
    uint32_t offset, nr_files, error_code; 
    uint64_t ret_val;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;
    DIR *dir;
    struct dirent *dirent = NULL;

    printf("Dispatching list operation (gref=%d).\n", req->u.flist.gref);
    /* Read the request, and list directory */
    offset = req->u.flist.offset;
    buf = file_name = xc_gnttab_map_grant_ref(mount->gnth,
                                        mount->dom_id,
                                        req->u.flist.gref,
                                        PROT_READ | PROT_WRITE);
   
    req_id = req->id;
    printf("Dir list issued for %s\n", file_name); 
    assert(BUFFER_SIZE > 
           strlen(file_name) + strlen(mount->export->export_path) + 1); 
    sprintf(full_path, "%s/%s", mount->export->export_path, file_name);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;

    ret_val = 0;
    nr_files = 0;
    dir = opendir(full_path);
    if(dir == NULL)
    {
        error_code = errno;
        goto error_out;
    }
    /* Skip offset dirs */
    dirent = readdir(dir);
    while(offset-- > 0 && dirent != NULL)
        dirent = readdir(dir);
    /* If there was any error with reading the directory, errno will be set */
    error_code = errno;
    /* Copy file names of the remaining non-NULL dirents into buf */
    assert(NAME_MAX < PAGE_SIZE >> 1);
    while(dirent != NULL && 
            (PAGE_SIZE - ((unsigned long)buf & PAGE_MASK) > NAME_MAX))
    {
        int curr_length = strlen(dirent->d_name) + 1;
        
        memcpy(buf, dirent->d_name, curr_length);
        buf += curr_length;
        dirent = readdir(dir);
        error_code = errno;
        nr_files++;
    }
error_out:    
    ret_val = ((nr_files << NR_FILES_SHIFT) & NR_FILES_MASK) | 
              ((error_code << ERROR_SHIFT) & ERROR_MASK) | 
              (dirent != NULL ? HAS_MORE_FLAG : 0);
    assert(xc_gnttab_munmap(mount->gnth, file_name, 1) == 0);
    
    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = ret_val;
}

void dispatch_chmod(struct mount *mount, struct fsif_request *req)
{
    int fd, ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;
    int32_t mode;

    printf("Dispatching file chmod operation (fd=%d, mode=%o).\n", 
            req->u.fchmod.fd, req->u.fchmod.mode);
    req_id = req->id;
    fd = req->u.fchmod.fd;
    mode = req->u.fchmod.mode;
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;

    ret = fchmod(fd, mode); 

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}

void dispatch_fs_space(struct mount *mount, struct fsif_request *req)
{
    char *file_name, full_path[BUFFER_SIZE];
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;
    struct statfs stat;
    int64_t ret;

    printf("Dispatching fs space operation (gref=%d).\n", req->u.fspace.gref);
    /* Read the request, and open file */
    file_name = xc_gnttab_map_grant_ref(mount->gnth,
                                        mount->dom_id,
                                        req->u.fspace.gref,
                                        PROT_READ);
   
    req_id = req->id;
    printf("Fs space issued for %s\n", file_name); 
    assert(BUFFER_SIZE > 
           strlen(file_name) + strlen(mount->export->export_path) + 1); 
    sprintf(full_path, "%s/%s", mount->export->export_path, file_name);
    assert(xc_gnttab_munmap(mount->gnth, file_name, 1) == 0);
    printf("Issuing fs space for %s\n", full_path);
    ret = statfs(full_path, &stat);
    if(ret >= 0)
        ret = stat.f_bsize * stat.f_bfree;

    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)ret;
}

void dispatch_file_sync(struct mount *mount, struct fsif_request *req)
{
    int fd;
    uint16_t req_id;
    unsigned short priv_id;
    struct fs_request *priv_req;

    req_id = req->id;
    fd = req->u.fsync.fd;
    printf("File sync issued for FD=%d\n", fd); 
   
    priv_id = get_request(mount, req);
    printf("Private id is: %d\n", priv_id);
    priv_req = &mount->requests[priv_id];

    /* Dispatch AIO read request */
    bzero(&priv_req->aiocb, sizeof(struct aiocb));
    priv_req->aiocb.aio_fildes = fd;
    assert(aio_fsync(O_SYNC, &priv_req->aiocb) >= 0);

     
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
}

void end_file_sync(struct mount *mount, struct fs_request *priv_req)
{
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    req_id = priv_req->req_shadow.id; 
    printf("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->ret_val = (uint64_t)aio_return(&priv_req->aiocb);
}

struct fs_op fopen_op     = {.type             = REQ_FILE_OPEN,
                             .dispatch_handler = dispatch_file_open,
                             .response_handler = NULL};
struct fs_op fclose_op    = {.type             = REQ_FILE_CLOSE,
                             .dispatch_handler = dispatch_file_close,
                             .response_handler = NULL};
struct fs_op fread_op     = {.type             = REQ_FILE_READ,
                             .dispatch_handler = dispatch_file_read,
                             .response_handler = end_file_read};
struct fs_op fwrite_op    = {.type             = REQ_FILE_WRITE,
                             .dispatch_handler = dispatch_file_write,
                             .response_handler = end_file_write};
struct fs_op fstat_op     = {.type             = REQ_STAT,
                             .dispatch_handler = dispatch_stat,
                             .response_handler = NULL};
struct fs_op ftruncate_op = {.type             = REQ_FILE_TRUNCATE,
                             .dispatch_handler = dispatch_truncate,
                             .response_handler = NULL};
struct fs_op fremove_op   = {.type             = REQ_REMOVE,
                             .dispatch_handler = dispatch_remove,
                             .response_handler = NULL};
struct fs_op frename_op   = {.type             = REQ_RENAME,
                             .dispatch_handler = dispatch_rename,
                             .response_handler = NULL};
struct fs_op fcreate_op   = {.type             = REQ_CREATE,
                             .dispatch_handler = dispatch_create,
                             .response_handler = NULL};
struct fs_op flist_op     = {.type             = REQ_DIR_LIST,
                             .dispatch_handler = dispatch_list,
                             .response_handler = NULL};
struct fs_op fchmod_op    = {.type             = REQ_CHMOD,
                             .dispatch_handler = dispatch_chmod,
                             .response_handler = NULL};
struct fs_op fspace_op    = {.type             = REQ_FS_SPACE,
                             .dispatch_handler = dispatch_fs_space,
                             .response_handler = NULL};
struct fs_op fsync_op     = {.type             = REQ_FILE_SYNC,
                             .dispatch_handler = dispatch_file_sync,
                             .response_handler = end_file_sync};


struct fs_op *fsops[] = {&fopen_op, 
                         &fclose_op, 
                         &fread_op, 
                         &fwrite_op, 
                         &fstat_op, 
                         &ftruncate_op, 
                         &fremove_op, 
                         &frename_op, 
                         &fcreate_op, 
                         &flist_op, 
                         &fchmod_op, 
                         &fspace_op, 
                         &fsync_op, 
                         NULL};
