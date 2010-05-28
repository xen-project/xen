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
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <unistd.h>
#include <ctype.h>
#include "fs-backend.h"
#include "fs-debug.h"

/* For debugging only */
#include <sys/time.h>
#include <time.h>


#define BUFFER_SIZE 1024

static int check_export_path(const char *export_path, const char *path)
{
    int i;
    if (!export_path || !path)
        return -1;
    if (strlen(path) < strlen(export_path))
        return -1;
    if (strstr(path, "..") != NULL)
        return -1;
    for (i = 0; i < strlen(path); i++) {
        if (!isascii(path[i]))
            return -1;
    }
    if (strncmp(export_path, path, strlen(export_path)))
        return -1;
    else
        return 0;
}

static unsigned short get_request(struct fs_mount *mount, struct fsif_request *req)
{
    unsigned short id = get_id_from_freelist(mount->freelist); 

    FS_DEBUG("Private Request id: %d\n", id);
    memcpy(&mount->requests[id].req_shadow, req, sizeof(struct fsif_request));
    mount->requests[id].active = 1;

    return id;
}

static int get_fd(struct fs_mount *mount)
{
    int i;

    for (i = 0; i < MAX_FDS; i++)
        if (mount->fds[i] == -1)
            return i;
    return -1;
}


static void dispatch_file_open(struct fs_mount *mount, struct fsif_request *req)
{
    char *file_name;
    int fd;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    FS_DEBUG("Dispatching file open operation (gref=%d).\n", req->u.fopen.gref);
    /* Read the request, and open file */
    file_name = xc_gnttab_map_grant_ref(mount->xch, mount->gnth,
                                        mount->dom_id,
                                        req->u.fopen.gref,
                                        PROT_READ);
   
    req_id = req->id;
    FS_DEBUG("File open issued for %s\n", file_name); 
    if (check_export_path(mount->export->export_path, file_name) < 0) {
        FS_DEBUG("Filename check failed\n");
        fd = -1;
        goto out;
    }
    fd = get_fd(mount);
    if (fd >= 0) {
        int real_fd = open(file_name, O_RDWR);
        if (real_fd < 0)
            fd = -1;
        else
        {
            mount->fds[fd] = real_fd;
            FS_DEBUG("Got FD: %d for real %d\n", fd, real_fd);
        }
    }
out:
    if (xc_gnttab_munmap(mount->xch, mount->gnth, file_name, 1) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)fd;
}

static void dispatch_file_close(struct fs_mount *mount, struct fsif_request *req)
{
    int ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    FS_DEBUG("Dispatching file close operation (fd=%d).\n", req->u.fclose.fd);
   
    req_id = req->id;
    if (req->u.fclose.fd < MAX_FDS) {
        int fd = mount->fds[req->u.fclose.fd];
        ret = close(fd);
        mount->fds[req->u.fclose.fd] = -1;
    } else
        ret = -1;
    FS_DEBUG("Got ret: %d\n", ret);
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}

#define MAX_GNTS 16
static void dispatch_file_read(struct fs_mount *mount, struct fsif_request *req)
{
    void *buf;
    int fd, count;
    uint16_t req_id;
    unsigned short priv_id;
    struct fs_request *priv_req;

    /* Read the request */
    assert(req->u.fread.len > 0); 
    count = (req->u.fread.len - 1) / XC_PAGE_SIZE + 1;
    assert(count <= FSIF_NR_READ_GNTS);
    buf = xc_gnttab_map_domain_grant_refs(mount->xch, mount->gnth,
                                          count,
                                          mount->dom_id,
                                          req->u.fread.grefs,
                                          PROT_WRITE);
   
    req_id = req->id;
    FS_DEBUG("File read issued for FD=%d (len=%"PRIu64", offest=%"PRIu64")\n", 
            req->u.fread.fd, req->u.fread.len, req->u.fread.offset); 

    if (req->u.fread.fd < MAX_FDS)
        fd = mount->fds[req->u.fread.fd];
    else
        fd = -1;

    priv_id = get_request(mount, req);
    FS_DEBUG("Private id is: %d\n", priv_id);
    priv_req = &mount->requests[priv_id];
    priv_req->page = buf;
    priv_req->count = count;
    priv_req->id = priv_id;

    /* Dispatch AIO read request */
    bzero(&priv_req->aiocb, sizeof(struct aiocb));
    priv_req->aiocb.aio_fildes = fd;
    priv_req->aiocb.aio_nbytes = req->u.fread.len;
    priv_req->aiocb.aio_offset = req->u.fread.offset;
    priv_req->aiocb.aio_buf = buf;
    priv_req->aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    priv_req->aiocb.aio_sigevent.sigev_signo = SIGUSR2;
    priv_req->aiocb.aio_sigevent.sigev_value.sival_ptr = priv_req;
    if (aio_read(&priv_req->aiocb) < 0) {
        FS_DEBUG("ERROR: aio_read failed errno=%d\n", errno);
        xc_gnttab_munmap(mount->xch, mount->gnth,
                         priv_req->page, priv_req->count);
        terminate_mount_request(mount);
    }

    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
}

static void end_file_read(struct fs_mount *mount, struct fs_request *priv_req)
{
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    /* Release the grant */
    if (xc_gnttab_munmap(mount->xch, mount->gnth,
                         priv_req->page, priv_req->count) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    req_id = priv_req->req_shadow.id; 
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)aio_return(&priv_req->aiocb);
}

static void dispatch_file_write(struct fs_mount *mount, struct fsif_request *req)
{
    void *buf;
    int fd, count;
    uint16_t req_id;
    unsigned short priv_id;
    struct fs_request *priv_req;

    /* Read the request */
    assert(req->u.fwrite.len > 0); 
    count = (req->u.fwrite.len - 1) / XC_PAGE_SIZE + 1;
    assert(count <= FSIF_NR_WRITE_GNTS);
    buf = xc_gnttab_map_domain_grant_refs(mount->xch, mount->gnth,
                                          count,
                                          mount->dom_id,
                                          req->u.fwrite.grefs,
                                          PROT_READ);
   
    req_id = req->id;
    FS_DEBUG("File write issued for FD=%d (len=%"PRIu64", offest=%"PRIu64")\n", 
            req->u.fwrite.fd, req->u.fwrite.len, req->u.fwrite.offset); 
   
    if (req->u.fwrite.fd < MAX_FDS)
        fd = mount->fds[req->u.fwrite.fd];
    else
        fd = -1;

    priv_id = get_request(mount, req);
    FS_DEBUG("Private id is: %d\n", priv_id);
    priv_req = &mount->requests[priv_id];
    priv_req->page = buf;
    priv_req->count = count;
    priv_req->id = priv_id;

    /* Dispatch AIO write request */
    bzero(&priv_req->aiocb, sizeof(struct aiocb));
    priv_req->aiocb.aio_fildes = fd;
    priv_req->aiocb.aio_nbytes = req->u.fwrite.len;
    priv_req->aiocb.aio_offset = req->u.fwrite.offset;
    priv_req->aiocb.aio_buf = buf;
    priv_req->aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    priv_req->aiocb.aio_sigevent.sigev_signo = SIGUSR2;
    priv_req->aiocb.aio_sigevent.sigev_value.sival_ptr = priv_req;
    if (aio_write(&priv_req->aiocb) < 0) {
        FS_DEBUG("ERROR: aio_write failed errno=%d\n", errno);
        xc_gnttab_munmap(mount->xch, mount->gnth,
                         priv_req->page, priv_req->count);
        terminate_mount_request(mount);
    }

     
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
}

static void end_file_write(struct fs_mount *mount, struct fs_request *priv_req)
{
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    /* Release the grant */
    if (xc_gnttab_munmap(mount->xch, mount->gnth,
                         priv_req->page, priv_req->count) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }
    
    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    req_id = priv_req->req_shadow.id; 
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)aio_return(&priv_req->aiocb);
}

static void dispatch_stat(struct fs_mount *mount, struct fsif_request *req)
{
    struct stat stat;
    int fd, ret;
    uint16_t req_id;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;

    req_id = req->id;
    if (req->u.fstat.fd < MAX_FDS)
        fd = mount->fds[req->u.fstat.fd];
    else
        fd = -1;

    FS_DEBUG("File stat issued for FD=%d\n", req->u.fstat.fd); 
   
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
   
    /* Stat, and create the response */ 
    ret = fstat(fd, &stat);
    FS_DEBUG("Mode=%o, uid=%d, a_time=%ld\n",
            stat.st_mode, stat.st_uid, (long)stat.st_atime);
    
    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.fstat.stat_ret = (uint32_t)ret;
    rsp->u.fstat.stat_mode  = stat.st_mode;
    rsp->u.fstat.stat_uid   = stat.st_uid;
    rsp->u.fstat.stat_gid   = stat.st_gid;
#ifdef BLKGETSIZE
    if (S_ISBLK(stat.st_mode)) {
	unsigned long sectors;
	if (ioctl(fd, BLKGETSIZE, &sectors)) {
	    perror("getting device size\n");
	    rsp->u.fstat.stat_size = 0;
	} else
	    rsp->u.fstat.stat_size = sectors << 9;
    } else
#endif
	rsp->u.fstat.stat_size  = stat.st_size;
    rsp->u.fstat.stat_atime = stat.st_atime;
    rsp->u.fstat.stat_mtime = stat.st_mtime;
    rsp->u.fstat.stat_ctime = stat.st_ctime;
}


static void dispatch_truncate(struct fs_mount *mount, struct fsif_request *req)
{
    int fd, ret;
    uint16_t req_id;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    int64_t length;

    req_id = req->id;
    length = req->u.ftruncate.length;
    FS_DEBUG("File truncate issued for FD=%d, length=%"PRId64"\n", req->u.ftruncate.fd, length); 
   
    if (req->u.ftruncate.fd < MAX_FDS)
        fd = mount->fds[req->u.ftruncate.fd];
    else
        fd = -1;

    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
   
    /* Stat, and create the response */ 
    ret = ftruncate(fd, length);

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}

static void dispatch_remove(struct fs_mount *mount, struct fsif_request *req)
{
    char *file_name;
    int ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    FS_DEBUG("Dispatching remove operation (gref=%d).\n", req->u.fremove.gref);
    /* Read the request, and open file */
    file_name = xc_gnttab_map_grant_ref(mount->xch, mount->gnth,
                                        mount->dom_id,
                                        req->u.fremove.gref,
                                        PROT_READ);
   
    req_id = req->id;
    FS_DEBUG("File remove issued for %s\n", file_name); 
    if (check_export_path(mount->export->export_path, file_name) < 0) {
        FS_DEBUG("Filename check failed\n");
        ret = -1;
    } else {
        ret = remove(file_name);
    }
    FS_DEBUG("Got ret: %d\n", ret);
    if (xc_gnttab_munmap(mount->xch, mount->gnth, file_name, 1) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}


static void dispatch_rename(struct fs_mount *mount, struct fsif_request *req)
{
    char *buf, *old_file_name, *new_file_name;
    int ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    FS_DEBUG("Dispatching rename operation (gref=%d).\n", req->u.fremove.gref);
    /* Read the request, and open file */
    buf = xc_gnttab_map_grant_ref(mount->xch, mount->gnth,
                                  mount->dom_id,
                                  req->u.frename.gref,
                                  PROT_READ);
   
    req_id = req->id;
    old_file_name = buf + req->u.frename.old_name_offset;
    new_file_name = buf + req->u.frename.new_name_offset;
    FS_DEBUG("File rename issued for %s -> %s (buf=%s)\n", 
            old_file_name, new_file_name, buf); 
    if (check_export_path(mount->export->export_path, old_file_name) < 0 ||
        check_export_path(mount->export->export_path, new_file_name) < 0) {
        FS_DEBUG("Filename check failed\n");
        ret = -1;
    } else {
        ret = rename(old_file_name, new_file_name);
    }
    FS_DEBUG("Got ret: %d\n", ret);
    if (xc_gnttab_munmap(mount->xch, mount->gnth, buf, 1) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}


static void dispatch_create(struct fs_mount *mount, struct fsif_request *req)
{
    char *file_name;
    int ret;
    int8_t directory;
    int32_t mode;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    FS_DEBUG("Dispatching file create operation (gref=%d).\n", req->u.fcreate.gref);
    /* Read the request, and create file/directory */
    mode = req->u.fcreate.mode;
    directory = req->u.fcreate.directory;
    file_name = xc_gnttab_map_grant_ref(mount->xch, mount->gnth,
                                        mount->dom_id,
                                        req->u.fcreate.gref,
                                        PROT_READ);
   
    req_id = req->id;
    if (check_export_path(mount->export->export_path, file_name) < 0) {
        FS_DEBUG("Filename check failed\n");
        ret = -1;
        goto out;
    }
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;

    if(directory)
    {
        FS_DEBUG("Issuing create for directory: %s\n", file_name);
        ret = mkdir(file_name, mode);
    }
    else
    {
        FS_DEBUG("Issuing create for file: %s\n", file_name);
        ret = get_fd(mount);
        if (ret >= 0) {
            int real_fd = creat(file_name, mode);
            if (real_fd < 0)
                ret = -1;
            else
            {
                mount->fds[ret] = real_fd;
                FS_DEBUG("Got FD: %d for real %d\n", ret, real_fd);
            }
        }
    }
out:
    if (xc_gnttab_munmap(mount->xch, mount->gnth, file_name, 1) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }
    FS_DEBUG("Got ret %d (errno=%d)\n", ret, errno);

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}

static void dispatch_list(struct fs_mount *mount, struct fsif_request *req)
{
    char *file_name, *buf;
    uint32_t offset = 0, nr_files = 0, error_code = 0;
    uint64_t ret_val;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;
    DIR *dir;
    struct dirent *dirent = NULL;

    FS_DEBUG("Dispatching list operation (gref=%d).\n", req->u.flist.gref);
    /* Read the request, and list directory */
    offset = req->u.flist.offset;
    buf = file_name = xc_gnttab_map_grant_ref(mount->xch, mount->gnth,
                                        mount->dom_id,
                                        req->u.flist.gref,
                                        PROT_READ | PROT_WRITE);
   
    req_id = req->id;
    FS_DEBUG("Dir list issued for %s\n", file_name); 
    if (check_export_path(mount->export->export_path, file_name) < 0) {
        FS_DEBUG("Filename check failed\n");
        error_code = 1;
        goto error_out;
    }
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;

    ret_val = 0;
    nr_files = 0;
    dir = opendir(file_name);
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
    if (NAME_MAX >= XC_PAGE_SIZE >> 1)
        goto error_out;
    while(dirent != NULL && 
            (XC_PAGE_SIZE - ((unsigned long)buf & XC_PAGE_MASK) > NAME_MAX))
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
    if (xc_gnttab_munmap(mount->xch, mount->gnth, file_name, 1) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = ret_val;
}

static void dispatch_chmod(struct fs_mount *mount, struct fsif_request *req)
{
    int fd, ret;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;
    int32_t mode;

    FS_DEBUG("Dispatching file chmod operation (fd=%d, mode=%o).\n", 
            req->u.fchmod.fd, req->u.fchmod.mode);
    req_id = req->id;
    if (req->u.fchmod.fd < MAX_FDS)
        fd = mount->fds[req->u.fchmod.fd];
    else
        fd = -1;

    mode = req->u.fchmod.mode;
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;

    ret = fchmod(fd, mode); 

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}

static void dispatch_fs_space(struct fs_mount *mount, struct fsif_request *req)
{
    char *file_name;
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;
    struct statvfs stat;
    int64_t ret;

    FS_DEBUG("Dispatching fs space operation (gref=%d).\n", req->u.fspace.gref);
    /* Read the request, and open file */
    file_name = xc_gnttab_map_grant_ref(mount->xch, mount->gnth,
                                        mount->dom_id,
                                        req->u.fspace.gref,
                                        PROT_READ);
   
    req_id = req->id;
    FS_DEBUG("Fs space issued for %s\n", file_name); 
    if (check_export_path(mount->export->export_path, file_name) < 0) {
        FS_DEBUG("Filename check failed\n");
        ret = -1;
    } else {
        ret = statvfs(file_name, &stat);
    }
    if(ret >= 0)
        ret = stat.f_bsize * stat.f_bfree;

    if (xc_gnttab_munmap(mount->xch, mount->gnth, file_name, 1) != 0) {
        FS_DEBUG("ERROR: xc_gnttab_munmap failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }
    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;


    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)ret;
}

static void dispatch_file_sync(struct fs_mount *mount, struct fsif_request *req)
{
    int fd;
    uint16_t req_id;
    unsigned short priv_id;
    struct fs_request *priv_req;

    req_id = req->id;
    if (req->u.fsync.fd < MAX_FDS)
        fd = mount->fds[req->u.fsync.fd];
    else
        fd = -1;

    FS_DEBUG("File sync issued for FD=%d\n", req->u.fsync.fd); 
   
    priv_id = get_request(mount, req);
    FS_DEBUG("Private id is: %d\n", priv_id);
    priv_req = &mount->requests[priv_id];
    priv_req->id = priv_id;

    /* Dispatch AIO read request */
    bzero(&priv_req->aiocb, sizeof(struct aiocb));
    priv_req->aiocb.aio_fildes = fd;
    priv_req->aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    priv_req->aiocb.aio_sigevent.sigev_signo = SIGUSR2;
    priv_req->aiocb.aio_sigevent.sigev_value.sival_ptr = priv_req;
    if (aio_fsync(O_SYNC, &priv_req->aiocb) < 0) {
        FS_DEBUG("ERROR: aio_fsync failed errno=%d\n", errno);
        terminate_mount_request(mount);
    }

    /* We can advance the request consumer index, from here on, the request
     * should not be used (it may be overrinden by a response) */
    mount->ring.req_cons++;
}

static void end_file_sync(struct fs_mount *mount, struct fs_request *priv_req)
{
    RING_IDX rsp_idx;
    fsif_response_t *rsp;
    uint16_t req_id;

    /* Get a response from the ring */
    rsp_idx = mount->ring.rsp_prod_pvt++;
    req_id = priv_req->req_shadow.id; 
    FS_DEBUG("Writing response at: idx=%d, id=%d\n", rsp_idx, req_id);
    rsp = RING_GET_RESPONSE(&mount->ring, rsp_idx);
    rsp->id = req_id; 
    rsp->u.ret_val = (uint64_t)aio_return(&priv_req->aiocb);
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
